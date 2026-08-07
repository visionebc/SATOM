"""Custody of the material that no automatic copy carries.

Two secrets gate recovery of this installation, and neither is replicated by
any mechanism -- deliberately:

    FERNET_KEY (.env)         opens every encrypted column in the database
    pki/internal-ca/ca.key    the sole issuer for the cluster's mTLS

Neither belongs in a backup bundle. A bundle is pushed off-box over SFTP with
a password that itself lives in an encrypted column, so a bundle carrying the
key that opens that column collapses the whole scheme into a single file:
lose one bundle, lose the estate. Bundles are also retained, mirrored to the
peer and copied to an external host -- exactly the properties you do not want
for the one secret that must not spread.

So this module does the two things that ARE safe.

1. It records a FINGERPRINT of each secret -- one-way, domain-separated and
   truncated -- in the bundle manifest. A restore can then NAME a key mismatch
   instead of producing a database of unreadable secrets with no explanation.
   This is the difference between a five-minute fix and a forensic afternoon.

2. It gives the operator an explicit, audited export path, and reports when
   that export has never happened. An absent backup you know about is a task;
   an absent backup you do not know about is the outage.

Nothing here ever writes a secret to disk on its own. The operator names the
destination, the same contract as the cluster join key.
"""
from __future__ import annotations

import hashlib
import logging
import os
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

#: Kinds of recovery material this module knows about.
FERNET = "fernet"
CA = "ca"
KINDS = (FERNET, CA)

#: app_settings key prefix. Only ever holds a fingerprint + timestamp, never
#: the material itself -- app_settings is dumped into every bundle.
ESCROW_KEY = "recovery.escrow.%s"

#: 64 bits is ample to identify a key; truncating keeps the digest useless as
#: an oracle for anything but equality, which is all a restore needs.
_FPR_LEN = 16


def fingerprint(material: bytes, domain: str) -> str:
    """One-way, domain-separated identity of *material*.

    Domain separation matters: without it the fingerprint of a Fernet key and
    of a CA key with the same bytes would collide, and a digest computed here
    could be replayed as a digest computed somewhere else. The separator byte
    stops ``domain + material`` pairs from aliasing each other.
    """
    if not material:
        return ""
    h = hashlib.sha256()
    h.update(b"satom-recovery/")
    h.update(domain.encode("utf-8"))
    h.update(b"\x00")
    h.update(material)
    return h.hexdigest()[:_FPR_LEN]


def fernet_key() -> bytes:
    """The live Fernet key, or b"" if this process has none."""
    raw = os.environ.get("FERNET_KEY") or ""
    return raw.encode("utf-8") if raw else b""


def fernet_fingerprint() -> str:
    return fingerprint(fernet_key(), FERNET)


def ca_dir() -> Path:
    from .cert_service import CA_DIR
    return Path(CA_DIR)


def ca_key_path() -> Path:
    return ca_dir() / "ca.key"


def holds_ca_key() -> bool:
    """True on the node that can issue. Only the primary should hold it."""
    try:
        return ca_key_path().is_file()
    except OSError:
        return False


def ca_fingerprint() -> str:
    """Fingerprint of the CA PRIVATE key, or "" where the node has none.

    Taken over the private key rather than the certificate on purpose: the
    certificate is public and travels freely, so a cert fingerprint would say
    nothing about whether the material that can still ISSUE survived.
    """
    if not holds_ca_key():
        return ""
    try:
        return fingerprint(ca_key_path().read_bytes(), CA)
    except OSError:
        return ""


def current_fingerprints() -> dict:
    """What this node holds right now. Safe to persist and to publish."""
    return {FERNET: fernet_fingerprint(), CA: ca_fingerprint()}


# --------------------------------------------------------------------------
# escrow ledger -- fingerprints and timestamps only, never the material
# --------------------------------------------------------------------------

def escrow_state() -> dict:
    """What has been exported, when, and by whom. Never the secret itself."""
    from .settings_store import get_json
    out = {}
    for kind in KINDS:
        rec = get_json(ESCROW_KEY % kind, None)
        out[kind] = rec if isinstance(rec, dict) else None
    return out


def record_escrow(kind: str, by: str = "") -> dict:
    """Note that *kind* was exported. Stores the fingerprint so a later export
    of a DIFFERENT key is visible as a new event rather than silently
    overwriting the record of the one an operator actually holds."""
    if kind not in KINDS:
        raise ValueError("unknown recovery material: %r" % (kind,))
    from .settings_store import set_json
    rec = {"fingerprint": current_fingerprints().get(kind, ""),
           "at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
           "by": by or "unknown"}
    set_json(ESCROW_KEY % kind, rec)
    return rec


def export_material(kinds=KINDS) -> dict:
    """Return the recovery material itself.

    The ONLY function here that handles secrets. It returns them; it never
    writes them. Choosing where a secret lands is the operator's decision, not
    a default -- a default destination is how a second uncontrolled copy gets
    created.
    """
    out = {}
    for kind in kinds:
        if kind == FERNET:
            key = fernet_key()
            if key:
                out[FERNET] = key.decode("utf-8")
        elif kind == CA:
            if holds_ca_key():
                try:
                    out[CA] = ca_key_path().read_text()
                except OSError as exc:
                    logger.warning("CA key unreadable: %s", exc)
        else:
            raise ValueError("unknown recovery material: %r" % (kind,))
    return out


# --------------------------------------------------------------------------
# manifest interop -- what a bundle records, and what a restore checks
# --------------------------------------------------------------------------

def manifest_lines() -> list:
    """Fingerprint lines for a bundle manifest.

    A node with no CA key emits an EMPTY value rather than omitting the line,
    so "this bundle predates fingerprinting" and "this node held no CA key"
    stay distinguishable when the bundle is read back.
    """
    fp = current_fingerprints()
    return ["fpr_%s: %s" % (k, fp.get(k, "")) for k in KINDS]


def parse_manifest(text: str) -> dict:
    """Fingerprints recorded in a manifest. Absent key => not recorded."""
    out = {}
    for line in (text or "").splitlines():
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        key = key.strip()
        if key.startswith("fpr_"):
            out[key[4:]] = val.strip()
    return out


def compare_manifest(text: str) -> list:
    """Findings for a restore. Empty list == nothing to say.

    Never raises and never blocks: a restore is a recovery action, and an
    operator who is mid-outage with the right key in hand must not be stopped
    by the check that exists to help them. It names the problem instead.
    """
    findings = []
    recorded = parse_manifest(text)
    live = current_fingerprints()

    if FERNET in recorded:
        was, now = recorded[FERNET], live.get(FERNET, "")
        if was and now and was != now:
            findings.append({
                "kind": FERNET, "severity": "critical",
                "detail": (
                    "This bundle was taken under a DIFFERENT FERNET_KEY "
                    "(bundle %s, this node %s). Every encrypted column in the "
                    "restored database -- appliance credentials, the backup "
                    "server password, the node identity key -- is "
                    "undecryptable here. Put the matching key in .env and "
                    "restart before trusting anything that decrypts."
                    % (was, now)),
            })
        elif was and not now:
            findings.append({
                "kind": FERNET, "severity": "warning",
                "detail": ("This node has no FERNET_KEY, so the restored "
                           "encrypted columns cannot be read. The bundle was "
                           "taken under key %s." % was),
            })
    return findings


# --------------------------------------------------------------------------
# diagnose
# --------------------------------------------------------------------------

def check() -> list:
    """Findings about recovery custody, worst first."""
    findings = []
    state = escrow_state()
    live = current_fingerprints()

    if not live.get(FERNET):
        findings.append({"kind": FERNET, "severity": "critical",
                         "detail": "no FERNET_KEY in this process"})
    else:
        rec = state.get(FERNET)
        if not rec:
            findings.append({
                "kind": FERNET, "severity": "warning",
                "detail": ("FERNET_KEY (%s) has never been exported. It is in "
                           ".env on this node and in no backup: losing the "
                           "disk makes every bundle's encrypted columns "
                           "unreadable. Run: satom execute export "
                           "recovery-key" % live[FERNET])})
        elif rec.get("fingerprint") and rec["fingerprint"] != live[FERNET]:
            findings.append({
                "kind": FERNET, "severity": "warning",
                "detail": ("the exported FERNET_KEY (%s) is not the one in use "
                           "(%s) -- the copy an operator holds no longer opens "
                           "this database"
                           % (rec["fingerprint"], live[FERNET]))})

    if holds_ca_key():
        rec = state.get(CA)
        if not rec:
            findings.append({
                "kind": CA, "severity": "warning",
                "detail": ("the internal CA key (%s) has never been exported. "
                           "This node is the sole issuer; the peer holds only "
                           "ca.crt, so losing this disk ends the ability to "
                           "issue and re-establish replication mTLS. Run: "
                           "satom execute export recovery-key"
                           % live.get(CA, "?"))})
        elif rec.get("fingerprint") and rec["fingerprint"] != live.get(CA):
            findings.append({
                "kind": CA, "severity": "warning",
                "detail": ("the exported CA key (%s) is not the one on disk "
                           "(%s)" % (rec["fingerprint"], live.get(CA)))})
    return findings
