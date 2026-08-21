"""Carrying certificate MATERIAL between appliances, and the two facts it rests on.

Both measured on FortiWeb 7.6.8 before a line was written, and both surprising:

1.  ``show`` inside the entry prints ``set certificate "<PEM>"`` AND
    ``set private-key "<PEM>"``. ``get`` prints neither (Subject/Issuer and an
    empty ``certificate:``), and REST prints neither for either field. So the
    CLI is the only channel, and ``show`` is the only verb.

2.  THE SCOPE IS NOT THE SAME ON EVERY BOX.

        fortiweb12 (ADOMs on)   `config system certificate local` at the top
                                level -> "Parsing error at 'system'"
        fortiweb13 (no ADOMs)   the same command at the top level -> accepted

    Verified end to end: ``lc-root-web`` read off fortiweb12 in ``adom`` scope
    and imported into fortiweb13 in ``device`` scope came back byte-identical
    (sha256 of the certificate and of the private key both unchanged).

A private key never leaves this layer. Nothing that goes into a plan, a report
or a log line carries one — only whether one was found.
"""
import pytest

from app.services import cert_carry as cc
from app.services import cert_ssh, cert_import


CERT = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"
KEY = "-----BEGIN PRIVATE KEY-----\nBBBB\n-----END PRIVATE KEY-----"
SHOW = ('config system certificate local\n'
        '    edit "c1"\n'
        '        set certificate "%s"\n'
        '        set private-key "%s"\n'
        '    next\n'
        'end\n' % (CERT, KEY))
LOCAL = "cmdb/system/certificate.local"
CA = "cmdb/system/certificate.ca"


# --------------------------------------------------------------------------- #
#  1. the prefix, and why missing it is worse than an error                     #
# --------------------------------------------------------------------------- #
def test_the_cmdb_prefix_is_stripped_before_the_spec_lookup():
    """The clone's urns carry ``cmdb/``; ``cert_import`` is keyed without it.

    A lookup that missed on the prefix would answer "REST can create this" for
    a collection whose cmdb POST answers 200 and DROPS the PEM.
    """
    assert cc.bare(LOCAL) == "system/certificate.local"
    assert cc.bare("system/certificate.local") == "system/certificate.local"
    assert cert_import.spec_for(cc.bare(LOCAL)) is not None
    assert cert_import.spec_for(LOCAL) is None      # the shape of the bug


def test_a_collection_rest_can_create_is_refused_here():
    with pytest.raises(cert_ssh.CertWriteViolation):
        cc.read_material(object(), "cmdb/server-policy/policy", "p1")


# --------------------------------------------------------------------------- #
#  2. the fields come from the spec, never from a copy                          #
# --------------------------------------------------------------------------- #
def test_required_fields_are_derived_from_the_spec():
    s = cert_import.SSH_ONLY_SPECS
    assert cc.required_fields(s["system/certificate.local"]) \
        == ("certificate", "private-key")
    # an XML CLIENT certificate calls its key `secret-key`, not `private-key`
    assert cc.required_fields(s["system/certificate.xml-client-certificate"]) \
        == ("certificate", "secret-key")
    # public material has no key at all — asking for one would make every CA
    # "incomplete" and unclonable
    assert cc.required_fields(s["system/certificate.ca"]) == ("certificate",)
    assert cc.required_fields(
        s["system/certificate.intermediate-certificate"]) == ("certificate",)


def test_every_ssh_only_collection_gets_fields_without_a_hand_kept_table():
    for spec in cert_import.SSH_ONLY_SPECS.values():
        fields = cc.required_fields(spec)
        assert fields[0] == "certificate"
        assert (spec.key_field in fields) if spec.key_field else len(fields) == 1


# --------------------------------------------------------------------------- #
#  3. parsing the show block                                                    #
# --------------------------------------------------------------------------- #
def test_both_pems_come_out_whole():
    mat = cc.parse_material(SHOW)
    assert mat["certificate"] == CERT
    assert mat["private-key"] == KEY


def test_a_multiline_pem_is_not_truncated_at_its_first_line():
    """A line-wise parser returns ``-----BEGIN CERTIFICATE-----`` and calls it a
    certificate. The destination would accept an object and serve nothing."""
    assert "\n" in cc.parse_material(SHOW)["certificate"]
    assert cc.parse_material(SHOW)["certificate"].endswith("-----")


def test_an_empty_field_is_ABSENT_not_an_empty_value():
    """``set certificate ""`` means the entry is a SHELL. Returning it as a
    value would let a shell be copied as though it were a certificate."""
    body = 'edit "c1"\n set certificate ""\n set private-key ""\nnext\n'
    assert cc.parse_material(body) == {}


def test_only_the_asked_for_fields_come_back():
    assert set(cc.parse_material(SHOW, fields=("certificate",))) == {"certificate"}


# --------------------------------------------------------------------------- #
#  4. complete vs ok — the distinction that stops half a certificate            #
# --------------------------------------------------------------------------- #
class FakeSess:
    """A CertScopeSSH that answers from fixtures. No device, no paramiko."""

    def __init__(self, body, scope="device", fail=""):
        self.body, self._scope_res, self.fail = body, scope, fail
        self.entered, self.left, self.shown = [], 0, []

    def connect(self):
        if self.fail == "connect":
            raise RuntimeError("auth failed")
        return self

    def enter_table(self, table):
        if self.fail == "scope":
            raise RuntimeError("the certificate table is not reachable")
        self.entered.append(table)
        return self._scope_res

    def show_entry(self, table, name):
        self.shown.append((table, name))
        return self.body

    def leave_table(self):
        self.left += 1

    def close(self):
        pass


def _read(monkeypatch, sess):
    monkeypatch.setattr(cc, "CertScopeSSH", lambda *a, **k: sess)
    return cc.read_material(object(), LOCAL, "c1")


def test_a_complete_read_reports_the_scope_it_used(monkeypatch):
    sess = FakeSess(SHOW, scope="adom")
    res = _read(monkeypatch, sess)
    assert res["ok"] and res["complete"] and res["missing"] == []
    assert res["scope"] == "adom"
    assert sess.entered == ["local"] and sess.shown == [("local", "c1")]
    assert set(res["material"]) == {"certificate", "private-key"}


def test_a_certificate_whose_key_the_box_did_not_print_is_INCOMPLETE(monkeypatch):
    """Copying its public half would create a certificate the destination can
    never serve with — an object that exists and reports present."""
    body = 'edit "c1"\n set certificate "%s"\nnext\n' % CERT
    res = _read(monkeypatch, FakeSess(body))
    assert res["ok"] is True            # the entry WAS read
    assert res["complete"] is False     # and it still cannot be carried
    assert res["missing"] == ["private-key"]
    assert "private-key" in res["reason"]


def test_an_unreachable_scope_never_looks_like_a_certificate_with_no_material(monkeypatch):
    res = _read(monkeypatch, FakeSess(SHOW, fail="scope"))
    assert res["ok"] is False and res["complete"] is False
    assert "not reachable" in res["reason"]


def test_a_session_that_cannot_connect_says_so(monkeypatch):
    res = _read(monkeypatch, FakeSess(SHOW, fail="connect"))
    assert res["ok"] is False and "auth failed" in res["reason"]


def test_an_entry_the_box_does_not_list_is_named(monkeypatch):
    res = _read(monkeypatch, FakeSess(""))
    assert res["ok"] is False and "does not list" in res["reason"]


def test_the_session_is_always_closed_out_of_its_scope(monkeypatch):
    sess = FakeSess(SHOW)
    _read(monkeypatch, sess)
    assert sess.left == 1


# --------------------------------------------------------------------------- #
#  5. carry never half-writes, and never returns a key                          #
# --------------------------------------------------------------------------- #
def test_an_incomplete_read_is_refused_not_partially_written(monkeypatch):
    calls = []
    monkeypatch.setattr(cc, "read_material",
                        lambda *a, **k: {"ok": True, "complete": False,
                                         "material": {"certificate": CERT},
                                         "missing": ["private-key"],
                                         "scope": "device",
                                         "reason": "no private-key"})
    monkeypatch.setattr(cert_ssh, "import_into",
                        lambda *a, **k: calls.append(a))
    out = cc.carry(object(), object(), LOCAL, "c1")
    assert out["carried"] is False and calls == []
    assert "no private-key" in out["reason"]


def test_a_successful_carry_passes_the_right_key_field(monkeypatch):
    seen = {}

    def fake_import(appl, collection, name, cert, key, **kw):
        seen.update(collection=collection, name=name, cert=cert, key=key)

    monkeypatch.setattr(cc, "read_material",
                        lambda *a, **k: {"ok": True, "complete": True,
                                         "material": {"certificate": CERT,
                                                      "private-key": KEY},
                                         "missing": [], "scope": "adom",
                                         "reason": ""})
    monkeypatch.setattr(cert_ssh, "import_into", fake_import)
    out = cc.carry(object(), object(), LOCAL, "c1")
    assert out["carried"] is True and out["scope"] == "adom"
    # the BARE collection, because that is what cert_import is keyed on
    assert seen["collection"] == "system/certificate.local"
    assert seen["cert"] == CERT and seen["key"] == KEY


def test_a_keyless_collection_sends_no_key(monkeypatch):
    seen = {}
    monkeypatch.setattr(cc, "read_material",
                        lambda *a, **k: {"ok": True, "complete": True,
                                         "material": {"certificate": CERT},
                                         "missing": [], "scope": "device",
                                         "reason": ""})
    monkeypatch.setattr(cert_ssh, "import_into",
                        lambda appl, coll, name, cert, key, **kw:
                        seen.update(key=key))
    assert cc.carry(object(), object(), CA, "ca1")["carried"] is True
    assert seen["key"] == ""


def test_carry_never_returns_material(monkeypatch):
    monkeypatch.setattr(cc, "read_material",
                        lambda *a, **k: {"ok": True, "complete": True,
                                         "material": {"certificate": CERT,
                                                      "private-key": KEY},
                                         "missing": [], "scope": "device",
                                         "reason": ""})
    monkeypatch.setattr(cert_ssh, "import_into", lambda *a, **k: "")
    out = cc.carry(object(), object(), LOCAL, "c1")
    blob = repr(out)
    assert "BEGIN" not in blob and "material" not in out
    assert set(out) == {"ok", "carried", "reason", "scope"}


def test_a_destination_that_refuses_it_is_not_reported_as_carried(monkeypatch):
    monkeypatch.setattr(cc, "read_material",
                        lambda *a, **k: {"ok": True, "complete": True,
                                         "material": {"certificate": CERT,
                                                      "private-key": KEY},
                                         "missing": [], "scope": "device",
                                         "reason": ""})

    def boom(*a, **k):
        raise RuntimeError("-7721 This certificate is invalid")

    monkeypatch.setattr(cert_ssh, "import_into", boom)
    out = cc.carry(object(), object(), LOCAL, "c1")
    assert out["carried"] is False and "-7721" in out["reason"]


# --------------------------------------------------------------------------- #
#  6. the wiring: BEFORE the first write, and only when asked                   #
# --------------------------------------------------------------------------- #
from app.services import policy_ops                                # noqa: E402
from app.services import clone as _clone                           # noqa: E402


class _Appl:
    def __init__(self, ident):
        self.id = ident
        self.name = "appl%s" % ident
        self.vdom = "root"


def _cert_item(name, urn=LOCAL):
    return _clone.CloneItem("Local Certificate", urn, None, name, "",
                            "object", 3, {"name": name}, "cert")


def _ctx(src, dst, enabled=True):
    return {"enabled": enabled, "src_appliance": src, "dst_appliance": dst,
            "rows": []}


def test_nothing_happens_unless_the_operator_asked(monkeypatch):
    """The clone's default posture is that key material is REPORTED and never
    carried. Reversing that silently would change what a run does."""
    monkeypatch.setattr(cc, "carry", lambda *a, **k: pytest.fail("carried!"))
    rows, blocking = policy_ops._resolve_certificates(
        [_cert_item("c1")], _ctx(_Appl(1), _Appl(2), enabled=False),
        dry_run=False)
    assert rows == [] and blocking == []
    assert policy_ops._resolve_certificates([_cert_item("c1")], None,
                                            dry_run=False) == ([], [])


def test_a_name_the_destination_already_has_is_left_alone(monkeypatch):
    """Overwriting a certificate the destination is already serving with is a
    change to live traffic nobody asked for."""
    monkeypatch.setattr(cc, "names_at", lambda appl, urn, **k: ["c1"])
    monkeypatch.setattr(cc, "carry", lambda *a, **k: pytest.fail("carried!"))
    rows, blocking = policy_ops._resolve_certificates(
        [_cert_item("c1")], _ctx(_Appl(1), _Appl(2)), dry_run=False)
    assert blocking == []
    assert rows[0]["action"] == "already at the destination" and rows[0]["ok"]


def test_the_destination_is_listed_once_per_collection_not_per_certificate(monkeypatch):
    calls = []
    monkeypatch.setattr(cc, "names_at",
                        lambda appl, urn, **k: calls.append(urn) or [])
    monkeypatch.setattr(cc, "carry", lambda *a, **k: {"carried": True,
                                                      "reason": "", "ok": True})
    policy_ops._resolve_certificates(
        [_cert_item("c1"), _cert_item("c2"), _cert_item("c3")],
        _ctx(_Appl(1), _Appl(2)), dry_run=False)
    assert calls == [LOCAL]


def test_the_same_certificate_named_twice_is_carried_once(monkeypatch):
    carried = []
    monkeypatch.setattr(cc, "names_at", lambda *a, **k: [])
    monkeypatch.setattr(cc, "carry",
                        lambda s, d, u, n, **k: carried.append(n) or
                        {"carried": True, "reason": "", "ok": True})
    rows, _ = policy_ops._resolve_certificates(
        [_cert_item("c1"), _cert_item("c1")], _ctx(_Appl(1), _Appl(2)),
        dry_run=False)
    assert carried == ["c1"] and len(rows) == 1


def test_a_same_device_clone_carries_nothing(monkeypatch):
    monkeypatch.setattr(cc, "carry", lambda *a, **k: pytest.fail("carried!"))
    one = _Appl(7)
    rows, blocking = policy_ops._resolve_certificates(
        [_cert_item("c1")], _ctx(one, one), dry_run=False)
    assert blocking == [] and rows[0]["action"] == "same device"


def test_a_dry_run_reads_nothing_and_writes_nothing(monkeypatch):
    monkeypatch.setattr(cc, "names_at", lambda *a, **k: [])
    monkeypatch.setattr(cc, "carry", lambda *a, **k: pytest.fail("carried!"))
    rows, blocking = policy_ops._resolve_certificates(
        [_cert_item("c1")], _ctx(_Appl(1), _Appl(2)), dry_run=True)
    assert blocking == [] and rows[0]["action"] == "would carry"


def test_a_failed_carry_is_BLOCKING(monkeypatch):
    monkeypatch.setattr(cc, "names_at", lambda *a, **k: [])
    monkeypatch.setattr(cc, "carry",
                        lambda *a, **k: {"carried": False, "ok": False,
                                         "reason": "the destination refused it"})
    items = [_cert_item("c1")]
    rows, blocking = policy_ops._resolve_certificates(
        items, _ctx(_Appl(1), _Appl(2)), dry_run=False)
    assert [r["name"] for r in blocking] == ["c1"]
    assert "NOT carried" in items[0].note


def test_a_destination_that_cannot_be_listed_does_not_silently_skip(monkeypatch):
    """An unreadable list is not "the destination has none" and not "it has it".
    Either shortcut ends with an object naming a certificate that is not there.
    """
    def boom(*a, **k):
        raise RuntimeError("SSH refused")

    monkeypatch.setattr(cc, "names_at", boom)
    monkeypatch.setattr(cc, "carry",
                        lambda *a, **k: {"carried": True, "ok": True,
                                         "reason": ""})
    rows, blocking = policy_ops._resolve_certificates(
        [_cert_item("c1")], _ctx(_Appl(1), _Appl(2)), dry_run=False)
    # it still TRIES the carry rather than assuming either answer
    assert rows[0]["action"] == "carried" and blocking == []


def test_only_certificate_collections_are_considered(monkeypatch):
    monkeypatch.setattr(cc, "names_at", lambda *a, **k: [])
    monkeypatch.setattr(cc, "carry", lambda *a, **k: {"carried": True,
                                                      "ok": True, "reason": ""})
    ordinary = _clone.CloneItem("Server Pool", "cmdb/server-policy/server-pool",
                                None, "pool1", "", "object", 2,
                                {"name": "pool1"}, "create")
    rows, _ = policy_ops._resolve_certificates(
        [ordinary, _cert_item("c1")], _ctx(_Appl(1), _Appl(2)), dry_run=False)
    assert [r["name"] for r in rows] == ["c1"]


def test_an_xml_client_certificate_carries_its_SECRET_KEY_not_a_private_key(monkeypatch):
    """The one collection whose key field is not ``private-key``.

    Reading the right field and then SENDING a hard-coded ``private-key`` would
    pass every test that only ever carries a Local certificate — the two names
    coincide there. This is the case that separates them.
    """
    XML = "cmdb/system/certificate.xml-client-certificate"
    seen = {}
    monkeypatch.setattr(cc, "read_material",
                        lambda *a, **k: {"ok": True, "complete": True,
                                         "material": {"certificate": CERT,
                                                      "secret-key": KEY},
                                         "missing": [], "scope": "device",
                                         "reason": ""})
    monkeypatch.setattr(cert_ssh, "import_into",
                        lambda appl, coll, name, cert, key, **kw:
                        seen.update(coll=coll, cert=cert, key=key))
    assert cc.carry(object(), object(), XML, "x1")["carried"] is True
    assert seen["coll"] == "system/certificate.xml-client-certificate"
    assert seen["key"] == KEY, "the secret-key must be the one that travels"


def test_the_key_field_is_read_AND_sent_from_the_same_place():
    """Both halves come from the spec. Two lookups would be two authors."""
    spec = cert_import.SSH_ONLY_SPECS["system/certificate.xml-client-certificate"]
    assert spec.key_field == "secret-key"
    assert spec.key_field in cc.required_fields(spec)
