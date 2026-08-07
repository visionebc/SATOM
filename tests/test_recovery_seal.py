"""Guards for sealed recovery custody.

The property under test is narrow and unforgiving: an envelope that reaches an
off-node destination must be useless to whoever holds it, and useful to the
operator who holds only a passphrase. Everything else here exists to stop the
seal from quietly becoming decorative -- a stale envelope, a weak passphrase,
a fingerprint an attacker can relabel, or a "sealed" state reported for a node
that never sealed anything.
"""
from __future__ import annotations

import json

import pytest

from app.services import recovery, recovery_seal as rs


GOOD = "correct-horse-battery-staple-42"


@pytest.fixture()
def seal_dir(tmp_path, monkeypatch):
    d = tmp_path / "recovery"
    monkeypatch.setattr(rs, "_seal_dir", lambda: d)
    return d


@pytest.fixture()
def material(monkeypatch):
    mat = {recovery.FERNET: "AAAA-fernet-key", recovery.CA: "-----BEGIN KEY-----"}
    monkeypatch.setattr(recovery, "export_material", lambda kinds=recovery.KINDS: dict(mat))
    monkeypatch.setattr(recovery, "current_fingerprints",
                        lambda: {recovery.FERNET: "ff11", recovery.CA: "cc22"})
    return mat


# ---------------------------------------------------------------- round trip

def test_a_sealed_envelope_reopens_with_the_right_passphrase(seal_dir, material):
    rs.seal(GOOD, by="tester")
    assert rs.unseal(GOOD) == material


def test_the_wrong_passphrase_is_refused_and_yields_nothing(seal_dir, material):
    rs.seal(GOOD, by="tester")
    with pytest.raises(rs.SealError):
        rs.unseal(GOOD + "x")


def test_the_envelope_never_contains_the_material_in_the_clear(seal_dir, material):
    """The whole reason this module may write where recovery.py may not."""
    rs.seal(GOOD, by="tester")
    raw = rs.seal_path().read_bytes()
    for secret in material.values():
        assert secret.encode() not in raw
    # and not base64-of-plaintext either
    import base64
    for secret in material.values():
        assert base64.b64encode(secret.encode()) not in raw


def test_the_passphrase_is_never_persisted_in_any_form(seal_dir, material):
    """No verifier, no hash, no hint. A verifier stored beside the ciphertext
    is an offline cracking oracle, and 'does it open' is the only check that
    is ever actually needed."""
    rs.seal(GOOD, by="tester")
    raw = rs.seal_path().read_text()
    assert GOOD not in raw
    import hashlib
    for algo in ("md5", "sha1", "sha256", "sha512"):
        digest = getattr(hashlib, algo)(GOOD.encode()).hexdigest()
        assert digest not in raw
        assert digest[:16] not in raw


# ------------------------------------------------------------- passphrase floor

def test_a_short_passphrase_is_refused_before_anything_is_written(seal_dir, material):
    with pytest.raises(rs.SealError):
        rs.seal("short", by="tester")
    assert not rs.seal_path().exists()


def test_an_empty_passphrase_is_refused(seal_dir, material):
    with pytest.raises(rs.SealError):
        rs.seal("", by="tester")


def test_a_generated_passphrase_clears_the_floor(seal_dir, material):
    """The generator must not produce something the sealer would reject."""
    gen = rs.generate_passphrase()
    assert len(gen) >= rs.MIN_PASSPHRASE
    rs.seal(gen, by="tester")
    assert rs.unseal(gen)


def test_generated_passphrases_are_not_repeated():
    assert len({rs.generate_passphrase() for _ in range(20)}) == 20


# ------------------------------------------------------------ fingerprint AAD

def test_fingerprints_are_readable_without_the_passphrase(seal_dir, material):
    """A restore must be able to tell 'this envelope holds the key I need'
    from 'this holds a key from two rotations ago' WITHOUT spending a guess."""
    rs.seal(GOOD, by="tester")
    st = rs.seal_state()
    assert st["fingerprints"][recovery.FERNET] == "ff11"
    assert st["fingerprints"][recovery.CA] == "cc22"


def test_relabelling_the_fingerprints_breaks_the_envelope(seal_dir, material):
    """The header is authenticated. Otherwise an envelope could be made to
    claim it holds a key it does not, and the restore check that exists to
    prevent a forensic afternoon would cause one."""
    rs.seal(GOOD, by="tester")
    doc = json.loads(rs.seal_path().read_text())
    doc["fingerprints"][recovery.FERNET] = "dead"
    rs.seal_path().write_text(json.dumps(doc))
    with pytest.raises(rs.SealError):
        rs.unseal(GOOD)


def test_truncating_the_ciphertext_is_detected(seal_dir, material):
    rs.seal(GOOD, by="tester")
    doc = json.loads(rs.seal_path().read_text())
    doc["ct"] = doc["ct"][:-8]
    rs.seal_path().write_text(json.dumps(doc))
    with pytest.raises(rs.SealError):
        rs.unseal(GOOD)


# ------------------------------------------------------------------- staleness

def test_a_seal_taken_under_a_different_key_is_reported_stale(seal_dir, material, monkeypatch):
    rs.seal(GOOD, by="tester")
    monkeypatch.setattr(recovery, "current_fingerprints",
                        lambda: {recovery.FERNET: "ff99", recovery.CA: "cc22"})
    st = rs.seal_state()
    assert st["sealed"] is True
    assert recovery.FERNET in st["stale"]
    assert recovery.CA not in st["stale"]


def test_a_current_seal_is_not_reported_stale(seal_dir, material):
    """Counterweight: a healthy seal must stay quiet. A check that always
    complains is a check operators learn to skip."""
    rs.seal(GOOD, by="tester")
    st = rs.seal_state()
    assert st["sealed"] is True
    assert st["stale"] == []


def test_no_seal_is_reported_as_absent_not_as_current(seal_dir, material):
    st = rs.seal_state()
    assert st["sealed"] is False
    assert st["stale"] == []


def test_an_unreadable_envelope_is_not_reported_as_sealed(seal_dir, material):
    """Corrupt must never read as fine. This is the failure mode this repo
    keeps hitting: a probe that cannot answer whose default means healthy."""
    seal_dir.mkdir(parents=True, exist_ok=True)
    rs.seal_path().write_text("{not json")
    st = rs.seal_state()
    assert st["sealed"] is False
    assert st["error"]


# ------------------------------------------------------------------- findings

def test_never_sealed_produces_a_finding(seal_dir, material):
    kinds = {f["kind"] for f in rs.check()}
    assert "seal" in kinds


def test_a_stale_seal_produces_a_finding_naming_the_key(seal_dir, material, monkeypatch):
    rs.seal(GOOD, by="tester")
    monkeypatch.setattr(recovery, "current_fingerprints",
                        lambda: {recovery.FERNET: "ff99", recovery.CA: "cc22"})
    findings = rs.check()
    assert findings
    assert any(recovery.FERNET in f["detail"] for f in findings)


def test_a_current_seal_produces_no_findings(seal_dir, material):
    rs.seal(GOOD, by="tester")
    assert rs.check() == []


# ----------------------------------------------------------------- durability

def test_the_envelope_lands_under_data_so_both_mechanisms_carry_it(monkeypatch, tmp_path):
    """data/ is the only directory the HA rsync AND the backup bundle both
    carry. Anywhere else is carried by neither -- which is how the publication
    overlay went stale on the standby for weeks."""
    monkeypatch.setattr(rs, "_data_dir", lambda: tmp_path / "data")
    assert (tmp_path / "data") in rs.seal_path().parents


def test_the_envelope_is_not_world_readable(seal_dir, material):
    rs.seal(GOOD, by="tester")
    assert rs.seal_path().stat().st_mode & 0o077 == 0


def test_sealing_twice_replaces_rather_than_accumulates(seal_dir, material):
    rs.seal(GOOD, by="tester")
    rs.seal(GOOD + "-rotated-passphrase", by="tester")
    assert rs.unseal(GOOD + "-rotated-passphrase")
    with pytest.raises(rs.SealError):
        rs.unseal(GOOD)
    assert len(list(seal_dir.glob("*.json"))) == 1
