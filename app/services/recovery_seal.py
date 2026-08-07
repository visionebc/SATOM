"""Sealed off-node custody for the two secrets no automatic copy carries.

``recovery.py`` deliberately never writes a secret to disk. This module writes
exactly one thing: an ENVELOPE whose contents are unreadable without a
passphrase the fleet does not hold.

Why an envelope at all, when ``recovery.py`` argues these secrets must not ride
in a bundle: the argument was never "the material must not leave the node", it
was "the material must not leave the node IN THE CLEAR". A bundle is retained,
mirrored to the peer and pushed to an external host over SFTP whose password
lives in a column ``FERNET_KEY`` opens -- so plaintext there collapses the whole
scheme into a single file. Ciphertext does not. Whoever steals a bundle holds
ciphertext; the operator, holding a passphrase and nothing else, can rebuild the
installation from any copy.

That asymmetry is the entire design. Everything below exists to keep it true.

Where the envelope lives, and why it is the only correct place::

    data/recovery/seal.json

``data/`` is the ONE directory both replication mechanisms carry: the HA
datasync rsyncs it to the peer, and the backup bundle packages it. A file
anywhere else is carried by neither -- which is exactly how
``publication-rules.local.json`` sat stale on the standby for weeks. ``data/``
is also gitignored, so no envelope can reach the published mirror.

Deliberately NOT here:

* **The passphrase**, in any form -- not stored, not hashed, not hinted. A
  verifier sitting beside the ciphertext is an offline cracking oracle, and
  "does it open" is the only check anyone ever actually needs.
* **Automatic re-sealing.** A seal that silently re-wraps itself under material
  the operator has not recorded is a seal the operator cannot open. Re-sealing
  is always an explicit act.

Deliberately IN THE CLEAR: the *fingerprints* of the sealed material. They are
one-way and truncated (see ``recovery.fingerprint``), and without them a restore
cannot tell "this envelope holds the key I need" from "this holds a key from two
rotations ago" without first spending a passphrase guess -- precisely the moment
an operator has none to spare. They are covered by the AEAD's associated data,
so an envelope cannot be relabelled to claim a key it does not hold.
"""
from __future__ import annotations

import base64
import json
import logging
import os
import secrets
from datetime import datetime
from pathlib import Path

from . import recovery

logger = logging.getLogger(__name__)

#: Envelope format. Stored so the KDF cost can be raised later without
#: stranding envelopes sealed under the old parameters.
SEAL_VERSION = 1

#: Floor for an operator-chosen passphrase. This guards a disaster-recovery
#: secret that will sit in off-site copies for years, so the relevant threat is
#: offline cracking, not a login prompt: there is no rate limit to hide behind.
MIN_PASSPHRASE = 16

#: scrypt work factor. ~32 MiB and ~100 ms per attempt on the class of node
#: this product installs on -- cheap once, ruinous a few billion times. Kept
#: below the aggressive end on purpose: sealing must not fail on a small node.
_SCRYPT_N = 1 << 15
_SCRYPT_R = 8
_SCRYPT_P = 1
_KEY_LEN = 32
_SALT_LEN = 16
_NONCE_LEN = 12

#: Generated passphrases. Word-shaped output is transcribed correctly off a
#: screen and read correctly down a phone line, which is how this secret will
#: actually travel. ~62 bits from five words plus a numeric tail.
_WORDS = (
    "anchor amber basin beacon cedar cinder copper cortex dagger delta ember "
    "falcon fathom garnet granite harbor indigo ivory jasper kernel lantern "
    "linen marble meadow nickel nimbus onyx orchid pewter pillar quartz quiver "
    "raven ridge saffron slate summit tundra umber vellum vertex walnut willow "
    "zenith zircon"
).split()


class SealError(Exception):
    """The envelope could not be created, opened, or trusted."""


# ---------------------------------------------------------------------------
# location
# ---------------------------------------------------------------------------

def _data_dir() -> Path:
    """The app's ``data/`` tree. Resolved from the app root, never from a
    configurable env var: this path decides whether the envelope is replicated
    at all, and a wrong answer fails silently."""
    return Path(__file__).resolve().parents[2] / "data"


def _seal_dir() -> Path:
    return _data_dir() / "recovery"


def seal_path() -> Path:
    return _seal_dir() / "seal.json"


# ---------------------------------------------------------------------------
# passphrase
# ---------------------------------------------------------------------------

def generate_passphrase(words: int = 5) -> str:
    """A passphrase strong enough to sit in off-site copies for years.

    Generated rather than prompted by default because operators asked to invent
    a passphrase under time pressure produce ones that do not survive an offline
    attack -- and this secret is only ever handled under time pressure.
    """
    picked = [secrets.choice(_WORDS) for _ in range(max(4, words))]
    return "-".join(picked) + "-%02d" % secrets.randbelow(100)


def _derive(passphrase: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    return Scrypt(salt=salt, length=_KEY_LEN, n=n, r=r, p=p).derive(
        passphrase.encode("utf-8"))


# ---------------------------------------------------------------------------
# seal / unseal
# ---------------------------------------------------------------------------

def seal(passphrase: str, by: str = "", kinds=recovery.KINDS) -> dict:
    """Wrap the recovery material in an envelope only *passphrase* opens.

    Returns the public header (never the material). Raises :class:`SealError`
    before writing anything if the passphrase is too weak or there is nothing
    to seal -- a half-written envelope reads as custody that does not exist.
    """
    if not isinstance(passphrase, str) or len(passphrase) < MIN_PASSPHRASE:
        raise SealError(
            "passphrase must be at least %d characters: this envelope will sit "
            "in off-site copies where an attacker can grind it offline with no "
            "rate limit" % MIN_PASSPHRASE)

    material = recovery.export_material(kinds)
    if not material:
        raise SealError("this node holds none of the recovery material")

    fingerprints = {k: v for k, v in recovery.current_fingerprints().items()
                    if k in material}

    salt = os.urandom(_SALT_LEN)
    nonce = os.urandom(_NONCE_LEN)
    header = {
        "v": SEAL_VERSION,
        "kdf": {"name": "scrypt", "n": _SCRYPT_N, "r": _SCRYPT_R,
                "p": _SCRYPT_P, "salt": base64.b64encode(salt).decode()},
        "nonce": base64.b64encode(nonce).decode(),
        "fingerprints": fingerprints,
        "kinds": sorted(material),
        "at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "by": by or "unknown",
    }

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    key = _derive(passphrase, salt, _SCRYPT_N, _SCRYPT_R, _SCRYPT_P)
    ct = AESGCM(key).encrypt(nonce, json.dumps(material).encode("utf-8"),
                             _aad(header))

    doc = dict(header)
    doc["ct"] = base64.b64encode(ct).decode()

    d = _seal_dir()
    d.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(d, 0o700)
    except OSError:                                   # pragma: no cover
        pass
    tmp = seal_path().with_suffix(".tmp")
    tmp.write_text(json.dumps(doc, indent=2))
    os.chmod(tmp, 0o600)
    # Replace, never append: two envelopes are two passphrases, and the
    # operator holds one. os.replace is atomic, so a crash mid-write cannot
    # leave a truncated envelope where a working one used to be.
    os.replace(tmp, seal_path())
    logger.info("recovery seal written (%s)", ",".join(sorted(material)))
    return header


def _aad(header: dict) -> bytes:
    """Associated data for the AEAD.

    Everything the envelope asserts in the clear is authenticated, so the
    fingerprints cannot be edited to claim a different key. Without this, the
    check that exists to prevent a forensic afternoon would cause one.
    """
    return json.dumps({k: header[k] for k in
                       ("v", "kdf", "nonce", "fingerprints", "kinds")},
                      sort_keys=True).encode("utf-8")


def unseal(passphrase: str) -> dict:
    """Open the envelope. Returns the material; never writes it anywhere."""
    doc = _read()
    if doc is None:
        raise SealError("no sealed recovery envelope on this node")

    try:
        kdf = doc["kdf"]
        salt = base64.b64decode(kdf["salt"])
        nonce = base64.b64decode(doc["nonce"])
        ct = base64.b64decode(doc["ct"])
        header = {k: doc[k] for k in
                  ("v", "kdf", "nonce", "fingerprints", "kinds")}
    except (KeyError, ValueError, TypeError) as exc:
        raise SealError("sealed envelope is malformed: %s" % exc) from exc

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    key = _derive(passphrase, salt, int(kdf["n"]), int(kdf["r"]), int(kdf["p"]))
    try:
        plain = AESGCM(key).decrypt(nonce, ct, _aad(header))
    except Exception as exc:                          # cryptography: InvalidTag
        # One message for a wrong passphrase and for a tampered envelope, on
        # purpose: distinguishing them tells an attacker which of the two they
        # achieved, and tells the operator nothing they can act on differently.
        raise SealError(
            "could not open the sealed envelope: wrong passphrase, or the "
            "envelope has been altered") from exc
    try:
        return json.loads(plain.decode("utf-8"))
    except ValueError as exc:                         # pragma: no cover
        raise SealError("sealed envelope opened but its contents are not "
                        "readable: %s" % exc) from exc


def _read():
    p = seal_path()
    if not p.exists():
        return None
    return json.loads(p.read_text())


# ---------------------------------------------------------------------------
# state
# ---------------------------------------------------------------------------

def seal_state() -> dict:
    """What custody this node actually has. Never raises.

    ``sealed`` is True only for an envelope that was read and parsed. An
    unreadable envelope reports ``sealed: False`` with an ``error`` -- corrupt
    must never render as fine, which is the failure this product keeps hitting:
    a probe that cannot answer whose default value reads as healthy.
    """
    out = {"sealed": False, "fingerprints": {}, "kinds": [], "stale": [],
           "at": "", "by": "", "error": "", "path": str(seal_path())}
    try:
        doc = _read()
    except (OSError, ValueError) as exc:
        out["error"] = "sealed envelope is unreadable: %s" % exc
        return out
    if doc is None:
        return out

    fps = doc.get("fingerprints")
    if not isinstance(fps, dict):
        out["error"] = "sealed envelope has no fingerprint header"
        return out

    out.update(sealed=True, fingerprints=fps,
               kinds=list(doc.get("kinds") or sorted(fps)),
               at=doc.get("at", ""), by=doc.get("by", ""))

    live = recovery.current_fingerprints()
    # A key present in the envelope but rotated on the node is stale. A key the
    # node no longer holds at all is NOT stale -- the envelope is then the only
    # copy left, which is the envelope doing its job.
    out["stale"] = sorted(k for k, was in fps.items()
                          if live.get(k) and was and live[k] != was)
    return out


def check() -> list:
    """Findings about sealed custody, worst first. Empty == nothing to say."""
    findings = []
    st = seal_state()

    if st["error"]:
        findings.append({
            "kind": "seal", "severity": "critical",
            "detail": ("%s -- this node reports no usable off-node custody. "
                       "Re-seal with: satom execute seal recovery" % st["error"]),
        })
        return findings

    if not st["sealed"]:
        # Only worth saying if there is in fact something to seal. A node
        # holding no recovery material has nothing to lose here.
        if any(recovery.current_fingerprints().values()):
            findings.append({
                "kind": "seal", "severity": "warning",
                "detail": ("No sealed recovery envelope. FERNET_KEY and the "
                           "internal CA exist only on local disks: a bundle "
                           "restored onto a rebuilt node would hold encrypted "
                           "columns nothing can read. Seal them with: "
                           "satom execute seal recovery"),
            })
        return findings

    for kind in st["stale"]:
        findings.append({
            "kind": "seal", "severity": "warning",
            "detail": ("The sealed envelope holds an OLD %s (envelope %s, this "
                       "node %s). Restoring from it would not open this "
                       "installation. Re-seal with: satom execute seal recovery"
                       % (kind, st["fingerprints"].get(kind, "?"),
                          recovery.current_fingerprints().get(kind, "?"))),
        })
    return findings
