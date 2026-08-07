"""The operator manual must carry the recovery-custody facts, and must not
carry a hand-typed CLI command count.

Why this file exists. 1.7.0 shipped a whole custody subsystem — two CLI verbs,
a diagnostic, and a passphrase the operator has to store outside the fleet —
and the operator manual never mentioned it. Nothing failed: the feature worked,
the release notes described it, and the one document an operator actually reads
did not. A capability nobody is told about is a capability nobody uses, and a
passphrase nobody is told to write down is a passphrase that is lost the first
time it matters.

The second rule closes a rot class found in the same pass. Section 20 claimed
"94 commands in 34 groups" while the generated reference said 98 in 36 — the
number had been correct for exactly one release and then quietly aged, the same
way the footer carried `v1.0` through four. `docs/cli.md` is generated from
`deploy/satom_cli/tree.py` and gate-checked, so it cannot drift. Prose can.
The fix is not a better number: it is no number.
"""
from __future__ import annotations

import pathlib
import re

import pytest

DOCS = pathlib.Path(__file__).resolve().parents[1] / "docs"
GUIDE = DOCS / "user-guide.md"
CLI_DOC = DOCS / "cli.md"


def guide() -> str:
    return GUIDE.read_text(encoding="utf-8")


def section(text: str, number: int) -> str:
    """The body of `## <number>. ...` up to the next top-level heading."""
    m = re.search(r"^## %d\. .*?$(.*?)(?=^## \d+\. )" % number, text,
                  re.S | re.M)
    assert m, "section %d not found — the manual's structure changed" % number
    return m.group(1)


# --------------------------------------------------------------- anti-vacuity
def test_the_manual_has_the_sections_these_guards_read():
    """If the section extraction silently returned nothing, every content
    assertion below would pass on an empty string."""
    text = guide()
    for n in (11, 20, 32):
        assert len(section(text, n)) > 500, "section %d is implausibly short" % n


# --------------------------------------------------------- recovery custody
def test_the_backup_section_documents_the_sealed_envelope():
    body = section(guide(), 11).lower()
    assert "sealed envelope" in body or "seal.json" in body


def test_the_manual_says_a_bundle_alone_cannot_be_restored():
    """The load-bearing fact: the bundle holds ciphertext, not secrets. An
    operator who does not know this believes a bundle is a full recovery."""
    body = section(guide(), 11).lower()
    assert "unreadable secrets" in body


def test_the_manual_tells_the_operator_to_keep_the_passphrase_off_the_cluster():
    """The single instruction that decides whether the envelope is worth
    anything. Three replicated copies of a box nobody can open is not custody."""
    body = section(guide(), 11).lower()
    assert "not the cluster" in body or "outside the cluster" in body


def test_the_manual_says_sealing_happens_on_the_primary():
    """A standby seal cannot carry the CA key and is erased by the next
    datasync — both failure modes are silent."""
    body = section(guide(), 11).lower()
    assert "primary" in body and "standby" in body


@pytest.mark.parametrize("verb", [
    "satom execute seal recovery",
    "satom execute unseal recovery",
    "satom diagnose recovery",
])
def test_every_recovery_verb_is_named_in_the_manual(verb):
    assert verb in guide(), "%s is not documented for operators" % verb


def test_the_unreachable_envelope_symptom_is_in_troubleshooting():
    """The failure that made the envelope useless while reporting success.
    Troubleshooting is where an operator looks when a check is red."""
    assert "unreachable" in section(guide(), 32).lower()


# ------------------------------------------------------- no hand-typed count
_COUNT_RE = re.compile(r"(\d+)\s+commands\b", re.I)


def test_the_manual_does_not_hand_type_a_cli_command_count():
    """`docs/cli.md` is generated from the live tree and gate-checked; a number
    retyped into prose has no such guard and rots at the next command added."""
    hits = _COUNT_RE.findall(guide())
    assert not hits, (
        "the manual hard-codes a CLI command count %r — point at "
        "`satom show tree` or docs/cli.md instead, which cannot drift" % hits)


def test_the_generated_reference_is_the_one_that_carries_the_count():
    """Counterweight: the rule above must not be satisfied by deleting the
    count everywhere. The generated document still states it."""
    assert _COUNT_RE.search(CLI_DOC.read_text(encoding="utf-8"))


def test_the_console_section_points_at_the_live_tree():
    body = section(guide(), 20)
    assert "satom show tree" in body
