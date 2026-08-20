"""The shared certificate slot must never move backwards.

The HA pair shares an IMPORTED wildcard through ``data/pki-shared/``: the node
that has it publishes, the datasync carries the directory, the peer installs.
The nightly pass runs publish-then-install on EVERY node — and on the standby
that order silently defeated the whole mechanism. Publish overwrote the slot
with the (older) cert the standby still served; install then compared the slot
against that same cert, found them identical, and adopted nothing. Every run
reported success. Measured on satom-node-2 on 2026-08-20 with a slot holding a
cert 43 days fresher than the one being served.
"""
import json
from datetime import datetime, timedelta, timezone

import pytest

from app.services import cert_service as cs


def _iso(days):
    return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()


# --------------------------------------------------------------------- #
#  _expires_before — the comparison itself
# --------------------------------------------------------------------- #
def test_older_expires_before_newer():
    assert cs._expires_before(_iso(10), _iso(60)) is True


def test_newer_does_not_expire_before_older():
    assert cs._expires_before(_iso(60), _iso(10)) is False


def test_equal_dates_are_not_older():
    """Equal is not older: a re-issue with the same window must still publish,
    or a byte-different-but-same-validity cert could never reach the peer."""
    same = _iso(30)
    assert cs._expires_before(same, same) is False


def test_an_unreadable_date_never_blocks_a_publish():
    """A date we cannot parse is no opinion. Refusing on it would turn a
    corrupt meta/slot into a node that can never share its certificate."""
    assert cs._expires_before("not-a-date", _iso(60)) is False
    assert cs._expires_before(_iso(10), "not-a-date") is False
    assert cs._expires_before(None, _iso(60)) is False
    assert cs._expires_before(_iso(10), None) is False


# --------------------------------------------------------------------- #
#  _shared_slot_not_after — read the CERT, not the description
# --------------------------------------------------------------------- #
def test_an_empty_slot_has_no_date(tmp_path):
    assert cs._shared_slot_not_after(tmp_path / "a.crt", tmp_path / "a.key") is None


def test_an_unreadable_slot_has_no_date(tmp_path):
    crt, key = tmp_path / "a.crt", tmp_path / "a.key"
    crt.write_bytes(b"garbage"), key.write_bytes(b"garbage")
    assert cs._shared_slot_not_after(crt, key) is None


def test_the_date_comes_from_the_certificate_not_from_meta(tmp_path, monkeypatch):
    """meta.json describes the slot; the certificate IS the slot. A stale or
    hand-edited meta must not decide whether the pair moves backwards."""
    crt, key = tmp_path / "a.crt", tmp_path / "a.key"
    crt.write_bytes(b"CERT"), key.write_bytes(b"KEY")
    (tmp_path / "meta.json").write_text(json.dumps({"not_after": _iso(999)}))
    monkeypatch.setattr(cs, "validate_pem",
                        lambda c, k, ch=None: {"not_after": "2026-10-15T16:00:55+00:00"})
    assert cs._shared_slot_not_after(crt, key) == "2026-10-15T16:00:55+00:00"


# --------------------------------------------------------------------- #
#  publish_shared_cert — the refusal
# --------------------------------------------------------------------- #
def _wire(app, monkeypatch, tmp_path, served_not_after, slot_not_after):
    """A publish where THIS node serves `served_not_after` and the slot holds
    `slot_not_after`. Everything below the freshness question is stubbed."""
    crt, key, meta = tmp_path / "s.crt", tmp_path / "s.key", tmp_path / "s.json"
    if slot_not_after is not None:
        crt.write_bytes(b"SLOT"), key.write_bytes(b"SLOTKEY")
    ctx = app.app_context()
    ctx.push()
    monkeypatch.setattr(cs, "_reload_nginx", lambda: None, raising=False)
    served_crt, served_key = tmp_path / "served.crt", tmp_path / "served.key"
    served_crt.write_bytes(b"SERVED"), served_key.write_bytes(b"SERVEDKEY")
    monkeypatch.setattr(cs, "CRT", served_crt)
    monkeypatch.setattr(cs, "KEY", served_key)
    monkeypatch.setattr(cs, "SHARED_DIR", tmp_path)
    monkeypatch.setattr(cs, "_shared_paths", lambda: (crt, key, meta))
    monkeypatch.setattr(cs, "_shared_slot_not_after", lambda c, k: slot_not_after)
    monkeypatch.setattr(cs, "_meta", lambda: {"source": cs.SHARED_SOURCE})
    monkeypatch.setattr(cs, "validate_pem",
                        lambda c, k, ch=None: {"subject": "CN=x",
                                               "not_after": served_not_after,
                                               "days_left": 1})
    monkeypatch.setattr(cs, "cert_dns_names", lambda pem: ["*.example.net"])
    return crt, key, meta


def test_publish_refuses_to_overwrite_a_newer_slot(app, monkeypatch, tmp_path):
    crt, key, meta = _wire(app, monkeypatch, tmp_path, _iso(13), _iso(56))
    res = cs.publish_shared_cert(by="test")
    assert res["published"] is False
    assert "NEWER" in res["reason"]
    assert crt.read_bytes() == b"SLOT", "the newer certificate was overwritten"


def test_publish_writes_when_this_node_is_newer(app, monkeypatch, tmp_path):
    crt, key, meta = _wire(app, monkeypatch, tmp_path, _iso(56), _iso(13))
    res = cs.publish_shared_cert(by="test")
    assert res["published"] is True
    assert crt.read_bytes() == b"SERVED"


def test_publish_writes_into_an_empty_slot(app, monkeypatch, tmp_path):
    crt, key, meta = _wire(app, monkeypatch, tmp_path, _iso(56), None)
    assert cs.publish_shared_cert(by="test")["published"] is True
    assert crt.read_bytes() == b"SERVED"


def test_publish_writes_when_the_dates_are_equal(app, monkeypatch, tmp_path):
    same = _iso(30)
    crt, key, meta = _wire(app, monkeypatch, tmp_path, same, same)
    assert cs.publish_shared_cert(by="test")["published"] is True


def test_the_refusal_is_a_freshness_rule_not_a_role_check(app, monkeypatch, tmp_path):
    """A role-gated publish is wrong the moment the roles are swapped. The guard
    must fire on the PRIMARY too if the primary's cert is the older one."""
    monkeypatch.setattr(cs, "node_hostname", lambda: "satom-node-1")
    crt, key, meta = _wire(app, monkeypatch, tmp_path, _iso(5), _iso(80))
    assert cs.publish_shared_cert(by="test")["published"] is False


def test_the_reason_names_both_dates(app, monkeypatch, tmp_path):
    """"Refused" without the two dates cannot be acted on: the operator cannot
    tell a stale node from a stale slot."""
    served, slot = _iso(13), _iso(56)
    _wire(app, monkeypatch, tmp_path, served, slot)
    reason = cs.publish_shared_cert(by="test")["reason"]
    assert served in reason and slot in reason
