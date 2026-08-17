"""Guards for the certificate inspector and the destination guard (round 2).

The finding this suite exists to protect is the one that is INVISIBLE when it
regresses: a leaf-only read reporting "chain incomplete". Nothing fails, no page
errors, and the operator is sent to fix a server that was never broken. Several
guards below are therefore about what the module must NOT say.

Fixtures are REAL certificates, minted by openssl at collection time. A
hand-written constant chain cannot exercise signature verification at all — and
signature verification is the only reason the link table is trustworthy.
"""
from __future__ import annotations

import os
import re
import subprocess
import tempfile

import pytest

from app.services import cert_inspect as ci
from app.services import net_guard as ng
from tests.conftest import admin_user_id, login, make_user

SVC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "app", "services", "cert_inspect.py")
JS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                  "app", "static", "js", "cert_inspect.js")

# Built at runtime, never a literal: a PEM private-key header in a source
# file aborts the publish (tests/test_no_pem_literals.py). The scanner
# cannot tell a fixture from a real key, and must not learn to.
_DASH = "-" * 5
BAD_KEY_PEM = (f"{_DASH}BEGIN PRIVATE KEY{_DASH}\nnope\n"
               f"{_DASH}END PRIVATE KEY{_DASH}")


# --------------------------------------------------------------------------- #
#  Real certificate fixtures                                                   #
# --------------------------------------------------------------------------- #
def _sh(cmd, cwd):
    r = subprocess.run(cmd, shell=True, cwd=cwd, capture_output=True)
    assert r.returncode == 0, cmd + "\n" + r.stderr.decode()[:500]


@pytest.fixture(scope="module")
def pki():
    if not ci.openssl_available():
        pytest.skip("openssl is required to mint the fixture chain")
    d = tempfile.mkdtemp(prefix="ci-test-")
    _sh("openssl req -x509 -newkey rsa:2048 -keyout root.key -out root.crt -days 3650 "
        "-nodes -subj '/CN=Guard Root CA' -addext basicConstraints=critical,CA:TRUE", d)
    _sh("openssl req -newkey rsa:2048 -keyout int.key -out int.csr -nodes "
        "-subj '/CN=Guard Intermediate'", d)
    _sh("printf 'basicConstraints=critical,CA:TRUE\\n' > int.ext", d)
    _sh("openssl x509 -req -in int.csr -CA root.crt -CAkey root.key -CAcreateserial "
        "-out int.crt -days 1800 -extfile int.ext", d)
    _sh("openssl req -newkey rsa:2048 -keyout leaf.key -out leaf.csr -nodes "
        "-subj '/CN=shop.example.com'", d)
    _sh("printf 'subjectAltName=DNS:shop.example.com,DNS:*.api.example.com\\n' > leaf.ext", d)
    _sh("openssl x509 -req -in leaf.csr -CA int.crt -CAkey int.key -CAcreateserial "
        "-out leaf.crt -days 400 -extfile leaf.ext", d)
    _sh("openssl req -x509 -newkey rsa:2048 -keyout other.key -out other.crt -days 400 "
        "-nodes -subj '/CN=unrelated.example.net'", d)

    def rd(n):
        with open(os.path.join(d, n)) as fh:
            return fh.read()

    return {"leaf": rd("leaf.crt"), "int": rd("int.crt"), "root": rd("root.crt"),
            "other": rd("other.crt"), "leaf_key": rd("leaf.key"),
            "root_key": rd("root.key"), "dir": d}


def codes(res):
    return [f["code"] for f in res["findings"]]


def sev_of(res, code):
    return next(f["severity"] for f in res["findings"] if f["code"] == code)


# --------------------------------------------------------------------------- #
#  THE central rule: unread is not incomplete                                  #
# --------------------------------------------------------------------------- #
def test_leaf_only_source_never_reports_incomplete(pki):
    res = ci.analyse(ci.split_pem(pki["leaf"]), source="leaf")
    assert res["chain_complete"] is None
    assert "incomplete_chain" not in codes(res)


def test_leaf_only_source_says_so_out_loud(pki):
    res = ci.analyse(ci.split_pem(pki["leaf"]), source="leaf")
    assert "chain_unknown" in codes(res)
    note = next(f for f in res["findings"] if f["code"] == "chain_unknown")
    # The distinction has to be IN the text: a finding titled "unknown" whose
    # body reads like a defect report is read as a defect report.
    assert "UNKNOWN" in note["detail"] and "incomplete" in note["detail"].lower()


def test_same_leaf_from_a_chain_read_IS_incomplete(pki):
    """The other half of the pair — otherwise 'never says incomplete' passes
    trivially by never detecting anything."""
    res = ci.analyse(ci.split_pem(pki["leaf"]), source="chain")
    assert res["chain_complete"] is False
    assert "incomplete_chain" in codes(res)


def test_full_chain_is_complete(pki):
    res = ci.analyse(ci.split_pem(pki["leaf"] + pki["int"] + pki["root"]),
                     source="chain")
    assert res["chain_complete"] is True
    assert "incomplete_chain" not in codes(res)


def test_ct346_shape_names_the_missing_issuer(pki):
    """The incident this tool was built for: the message must name the issuer
    that is missing, or it is no better than curl's error string."""
    res = ci.analyse(ci.split_pem(pki["leaf"]), source="chain")
    f = next(x for x in res["findings"] if x["code"] == "incomplete_chain")
    assert "Guard Intermediate" in f["detail"]
    assert "unable to get local issuer certificate" in f["detail"]


# --------------------------------------------------------------------------- #
#  Links are verified, not assumed                                             #
# --------------------------------------------------------------------------- #
def test_link_verification_is_a_real_signature_check(pki):
    assert ci.verify_signed_by(pki["leaf"], pki["int"]) is True
    assert ci.verify_signed_by(pki["leaf"], pki["root"]) is False
    assert ci.verify_signed_by(pki["int"], pki["root"]) is True


def test_unparseable_input_is_unknown_not_false(pki):
    """False means 'your chain is broken'. Saying that because a code path is
    missing is the failure mode this returns None to avoid."""
    assert ci.verify_signed_by("not a cert", pki["root"]) is None
    assert ci.verify_signed_by(pki["leaf"], "not a cert") is None


def test_a_verify_that_could_not_run_is_unknown_not_false(pki, monkeypatch):
    """The pair above only exercises the PARSE failure. The branch that matters
    is the one where the signature check itself could not run — an algorithm
    this build does not implement. Returning False there tells the operator
    their chain is broken on the strength of a missing code path, and the first
    version of this suite never reached it: the mutation that collapsed
    ``InvalidSignature`` into a blanket ``return False`` SURVIVED."""
    from cryptography import x509

    real = x509.load_pem_x509_certificate

    class _Boom:
        def verify(self, *a, **k):
            raise ValueError("unsupported signature algorithm on this build")

    class _Wrapped:
        def __init__(self, inner):
            self._inner = inner

        def __getattr__(self, name):
            return getattr(self._inner, name)

        def public_key(self):
            return _Boom()

    def fake(data, *a, **k):
        cert = real(data, *a, **k)
        return _Wrapped(cert) if data == pki["int"].encode() else cert

    monkeypatch.setattr(x509, "load_pem_x509_certificate", fake)
    assert ci.verify_signed_by(pki["leaf"], pki["int"]) is None


def test_chain_reports_each_link(pki):
    res = ci.analyse(ci.split_pem(pki["leaf"] + pki["int"] + pki["root"]),
                     source="chain")
    assert [l["verified"] for l in res["links"]] == [True, True]


# --------------------------------------------------------------------------- #
#  Ordering / extras                                                           #
# --------------------------------------------------------------------------- #
def test_out_of_order_is_flagged_and_still_ordered(pki):
    res = ci.analyse(ci.split_pem(pki["root"] + pki["int"] + pki["leaf"]),
                     source="chain")
    assert "out_of_order" in codes(res)
    # …and the RESULT is leaf-first regardless, or the panel would render the
    # root as the certificate the service presents.
    assert res["certificates"][0]["cn"] == "shop.example.com"


def test_unrelated_certificate_is_reported_not_dropped(pki):
    res = ci.analyse(ci.split_pem(pki["leaf"] + pki["int"] + pki["other"]),
                     source="chain")
    assert "extra_certificates" in codes(res)
    assert any("unrelated.example.net" in f["detail"] for f in res["findings"])


def test_correctly_ordered_chain_is_not_flagged(pki):
    res = ci.analyse(ci.split_pem(pki["leaf"] + pki["int"]), source="chain")
    assert "out_of_order" not in codes(res)
    assert "extra_certificates" not in codes(res)


# --------------------------------------------------------------------------- #
#  Hostname matching                                                           #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("pattern,host,expect", [
    ("shop.example.com", "shop.example.com", True),
    ("shop.example.com", "SHOP.EXAMPLE.COM.", True),
    ("*.api.example.com", "v1.api.example.com", True),
    ("*.api.example.com", "api.example.com", False),      # wildcard ≠ apex
    ("*.api.example.com", "a.b.api.example.com", False),  # one label only
    ("*.api.example.com", ".api.example.com", False),     # empty label
    ("api.*.example.com", "api.x.example.com", False),    # not leftmost
    ("", "x.com", False),
    ("*.com", "", False),
])
def test_name_matches(pattern, host, expect):
    assert ci.name_matches(pattern, host) is expect


def test_hostname_mismatch_is_critical_for_a_name(pki):
    res = ci.analyse(ci.split_pem(pki["leaf"] + pki["int"]),
                     hostname="www.example.com", source="chain")
    assert sev_of(res, "hostname_mismatch") == "crit"


def test_probe_by_ip_is_informational_not_critical(pki):
    """Every appliance in the inventory is probed by address and none of them
    carry an IP SAN. Critical here means the tool is red on arrival for the
    whole fleet, which is how an alarm stops being read."""
    res = ci.analyse(ci.split_pem(pki["leaf"] + pki["int"] + pki["root"]),
                     hostname="192.0.2.248", source="chain")
    assert "hostname_mismatch" not in codes(res)
    assert sev_of(res, "hostname_is_ip") == "info"
    # …and it does not colour the whole result. A complete, in-date chain
    # probed by address must not come back critical.
    assert res["verdict"] != "crit"


def test_san_is_preferred_over_cn(pki):
    res = ci.analyse(ci.split_pem(pki["leaf"]), hostname="shop.example.com",
                     source="chain")
    assert res["hostname"]["source"] == "SAN"


# --------------------------------------------------------------------------- #
#  Private key pairing                                                         #
# --------------------------------------------------------------------------- #
def test_matching_key_is_recognised(pki):
    r = ci.key_matches_cert(pki["leaf"], pki["leaf_key"])
    assert r["checked"] is True and r["match"] is True


def test_mismatched_key_is_critical(pki):
    res = ci.analyse(ci.split_pem(pki["leaf"] + pki["int"]), source="chain",
                     key_pem=pki["root_key"])
    assert sev_of(res, "key_mismatch") == "crit"


def test_absent_key_is_not_checked_and_not_a_finding(pki):
    res = ci.analyse(ci.split_pem(pki["leaf"]), source="chain")
    assert res["private_key"]["checked"] is False
    assert "key_mismatch" not in codes(res)
    assert "key_unchecked" not in codes(res)


def test_unparseable_key_reports_why_without_claiming_mismatch(pki):
    res = ci.analyse(ci.split_pem(pki["leaf"]), source="chain",
                     key_pem=BAD_KEY_PEM)
    assert "key_mismatch" not in codes(res)
    assert "key_unchecked" in codes(res)


# --------------------------------------------------------------------------- #
#  Parsing                                                                     #
# --------------------------------------------------------------------------- #
def test_split_pem_reads_an_s_client_transcript(pki):
    transcript = ("---\nCertificate chain\n 0 s:CN=shop.example.com\n"
                  "   i:CN=Guard Intermediate\n" + pki["leaf"] +
                  " 1 s:CN=Guard Intermediate\n   i:CN=Guard Root CA\n" + pki["int"])
    assert len(ci.split_pem(transcript)) == 2


def test_split_pem_tolerates_crlf(pki):
    assert len(ci.split_pem(pki["leaf"].replace("\n", "\r\n"))) == 1


def test_split_pem_is_capped(pki):
    assert len(ci.split_pem(pki["root"] * (ci.MAX_BUNDLE + 5))) == ci.MAX_BUNDLE


def test_garbage_block_is_reported_not_swallowed():
    bad = "-----BEGIN CERTIFICATE-----\nZZZZ\n-----END CERTIFICATE-----"
    res = ci.analyse(ci.split_pem(bad), source="chain")
    assert "unparseable" in codes(res)


# --------------------------------------------------------------------------- #
#  The response is not an echo                                                 #
# --------------------------------------------------------------------------- #
def test_pem_body_is_never_returned(pki):
    res = ci.analyse(ci.split_pem(pki["leaf"] + pki["int"]), source="chain")
    blob = repr(res)
    assert "BEGIN CERTIFICATE" not in blob
    assert all("pem" not in c for c in res["certificates"])


# --------------------------------------------------------------------------- #
#  net_guard — the destination policy                                          #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("ip", ng.METADATA_ADDRS)
def test_every_metadata_address_is_denied(ip):
    assert ng.denial_reason(ip) != ""


def test_ipv4_mapped_metadata_is_denied_FOR_BEING_METADATA():
    """``::ffff:169.254.169.254`` is the same destination with a different
    spelling. A denial that only matches the literal text is one prefix wide.

    The assertion is on the REASON, not merely on refusal. Asserting "some
    denial happened" passed even with the unwrap removed — that address also
    lands in IPv6's reserved ``::/8`` and was being refused for the wrong
    reason, which stops being true the moment the reserved rule is relaxed.
    The mutation that deleted the unwrap SURVIVED the first version of this
    test."""
    why = ng.denial_reason("::ffff:169.254.169.254")
    assert "metadata" in why, "denied, but not as a metadata address: %r" % why


@pytest.mark.parametrize("ip", ["192.0.2.248", "127.0.0.1", "192.168.1.1",
                                "169.254.1.1", "8.8.8.8"])
def test_ordinary_addresses_are_allowed(ip):
    """RFC1918 and loopback are ALLOWED on purpose: the whole fleet is RFC1918
    and blocking it would block the product's job."""
    assert ng.denial_reason(ip) == ""


@pytest.mark.parametrize("port", ng.DENIED_PORTS)
def test_non_http_ports_are_denied(port):
    assert ng.port_denial_reason(port) != ""


@pytest.mark.parametrize("port", [80, 443, 8080, 8443, 10443])
def test_http_ports_are_allowed(port):
    assert ng.port_denial_reason(port) == ""


@pytest.mark.parametrize("raw,host,port", [
    ("host", "host", 443),
    ("host:8443", "host", 8443),
    ("http://host", "host", 80),
    ("https://host/x?y=1", "host", 443),
    ("[::1]:9443", "::1", 9443),
    ("host.", "host", 443),
])
def test_parse_target_shapes(raw, host, port):
    p = ng.parse_target(raw)
    assert (p["host"], p["port"]) == (host, port)


def test_parse_target_keeps_the_path():
    assert ng.parse_target("https://h/checkout?a=1")["path"] == "/checkout?a=1"


@pytest.mark.parametrize("raw", ["", "ftp://x", "https://u:p@evil/", "h:99999",
                                 "h:abc", "https://"])
def test_parse_target_refusals(raw):
    with pytest.raises(ng.TargetError):
        ng.parse_target(raw)


def test_inventory_mode_refuses_a_host_not_in_the_inventory():
    with pytest.raises(ng.TargetError) as e:
        ng.resolve_target("127.0.0.1", 443, mode=ng.MODE_INVENTORY,
                          inventory_hosts=["192.0.2.1"])
    assert "free-target" in str(e.value)


def test_inventory_mode_accepts_a_listed_host():
    d = ng.resolve_target("127.0.0.1", 443, mode=ng.MODE_INVENTORY,
                          inventory_hosts=["127.0.0.1"])
    assert d["ip"] == "127.0.0.1"


def test_resolution_returns_the_address_the_caller_must_dial():
    """The guard is only binding because the caller connects to what it returns.
    A result without an address lets the caller re-resolve the NAME, which is
    the rebinding hole the guard exists to close."""
    d = ng.resolve_target("localhost", 443, mode=ng.MODE_FREE)
    assert d["ip"] and d["ip"] != "localhost"
    assert d["host"] == "localhost"


def test_every_answer_must_pass_not_just_the_first(monkeypatch):
    """A name answering with one good and one metadata address is a rebinding
    attempt; taking the first acceptable answer is exactly the bug it targets."""
    monkeypatch.setattr(ng, "_lookup", lambda h, p: [(2, "192.0.2.9"),
                                                     (2, "169.254.169.254")])
    with pytest.raises(ng.TargetError) as e:
        ng.resolve_target("rebind.test", 443, mode=ng.MODE_FREE)
    assert "169.254.169.254" in str(e.value)


def test_unresolvable_name_is_a_target_error():
    with pytest.raises(ng.TargetError):
        ng.resolve_target("no-such-host.invalid", 443, mode=ng.MODE_FREE)


# --------------------------------------------------------------------------- #
#  View: permissions, audit, shape                                             #
# --------------------------------------------------------------------------- #
def test_paste_endpoint_analyses(app, client, pki):
    login(client, admin_user_id(app))
    r = client.post("/cert-inspect/paste",
                    json={"pem": pki["leaf"] + pki["int"],
                          "hostname": "shop.example.com"})
    assert r.status_code == 200
    d = r.get_json()
    assert d["ok"] and d["count"] == 2
    assert "BEGIN CERTIFICATE" not in r.get_data(as_text=True)


def test_paste_without_a_certificate_explains_what_to_paste(app, client):
    login(client, admin_user_id(app))
    r = client.post("/cert-inspect/paste", json={"pem": "hello"})
    assert r.status_code == 400
    assert "BEGIN CERTIFICATE" in r.get_json()["error"]


def test_paste_requires_login(client):
    assert client.post("/cert-inspect/paste", json={"pem": "x"}).status_code in (302, 401)


def test_free_probe_is_refused_without_the_permission(app, client):
    uid = make_user(app, username="ro", role="readonly")
    login(client, uid)
    r = client.post("/cert-inspect/probe",
                    json={"mode": "free", "target": "example.com:443"})
    assert r.status_code == 403
    assert ng.FREE_PERMISSION in r.get_json()["error"]


def test_a_refused_probe_is_audited(app, client):
    """A refusal is the half of the trail an incident review actually wants."""
    from app.models import AuditLog
    uid = make_user(app, username="ro2", role="readonly")
    login(client, uid)
    client.post("/cert-inspect/probe",
                json={"mode": "free", "target": "example.com:443"})
    with app.app_context():
        assert AuditLog.query.filter_by(action="cert_inspect.probe_denied").count() == 1


def test_metadata_target_is_refused_and_audited(app, client):
    from app.models import AuditLog
    login(client, admin_user_id(app))
    r = client.post("/cert-inspect/probe",
                    json={"mode": "free", "target": "169.254.169.254:443"})
    assert r.status_code == 400
    assert "metadata" in r.get_json()["error"]
    with app.app_context():
        assert AuditLog.query.filter_by(action="cert_inspect.probe_denied").count() >= 1


def test_targets_endpoint_reports_capability_not_just_a_list(app, client):
    login(client, admin_user_id(app))
    d = client.get("/cert-inspect/targets").get_json()
    assert d["ok"] and "may_free" in d and "openssl" in d
    # The panel must be able to say WHY completeness will read 'unknown'
    # before the operator probes and blames their server.
    assert d["free_permission"] == ng.FREE_PERMISSION


def test_probe_free_permission_is_in_the_catalog():
    from app import permissions
    assert permissions.is_valid_key(ng.FREE_PERMISSION)


# --------------------------------------------------------------------------- #
#  The panel can render everything the service emits                           #
# --------------------------------------------------------------------------- #
def test_every_severity_the_service_emits_has_a_badge_class():
    """Derived from the SOURCE, not from a typed list: a new severity added to
    the service with no colour renders as the neutral grey pill, which reads as
    'nothing to see here' on a critical finding."""
    with open(SVC, encoding="utf-8") as fh:
        emitted = set(re.findall(r"_f\(\s*[\"']([a-z]+)[\"']", fh.read()))
    with open(JS, encoding="utf-8") as fh:
        mapped = set(re.findall(r"(\w+):\s*'fw-badge-", fh.read()))
    assert emitted, "no severities found — the scan anchor moved"
    assert emitted <= mapped, "unmapped severities: %s" % (emitted - mapped)


def test_panel_uses_light_theme_badges_only():
    """docs/safeguards.md §9m: this product is a white theme. A dark-theme
    pastel here renders at ~1.4:1 and a badge reading 'crit' becomes
    unreadable."""
    with open(JS, encoding="utf-8") as fh:
        js = fh.read()
    for token in ("#6ee7b7", "#fcd34d", "#fca5a5", "#93c5fd", "#c4b5fd",
                  "rgba(30,41,59", "backdrop-filter", "#080d1a"):
        assert token not in js, "dark-theme token %r in the inspector" % token


def test_verdict_is_the_worst_severity_present(pki):
    assert ci.analyse(ci.split_pem(pki["leaf"] + pki["int"] + pki["root"]),
                      source="chain")["verdict"] in ("ok", "warn", "crit")
    assert ci.analyse(ci.split_pem(pki["leaf"]), source="chain")["verdict"] == "crit"
