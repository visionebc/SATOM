"""Guards for the one property that makes a sealed envelope worth sealing.

``satom execute seal recovery`` exists so FERNET_KEY and the internal CA
reach the two places that carry them off this disk: the HA datasync, and
every backup bundle. Both of those read as the SERVICE ACCOUNT.

The command runs as root (``needs_root=True``). On 2026-08-07 it therefore
wrote ``data/recovery/`` as ``drwx------ root root`` with a 0600 file inside,
and the service account got Permission denied on both. The envelope existed,
was cryptographically perfect, and was structurally incapable of reaching
either destination it was built for -- while ``diagnose recovery`` dropped
the "no sealed envelope" finding and reported the durability problem solved.

That is worse than no envelope at all: no envelope tells the truth.

So the guards here are about REACHABILITY, not about cryptography:

  * sealing leaves the envelope owned by whoever owns the app tree, and
  * a probe that cannot be READ by the copy mechanisms says so, loudly,
    instead of reporting the seal as fine because root happened to ask.

The counterweights matter as much: a healthy node must produce no finding,
and the fix must not widen the file's permissions to buy reachability.
"""
from __future__ import annotations

import json
import os
import stat as stat_mod
import sys
from pathlib import Path

import pytest

from app.services import recovery, recovery_seal


PASS = "correct horse battery staple thing"


@pytest.fixture()
def sealed(monkeypatch, tmp_path):
    """A node tree with one real sealed envelope in it."""
    app_dir = tmp_path / "app"
    (app_dir / "data").mkdir(parents=True)
    # The tree owner is whoever owns app_dir. In the test that is us, which is
    # exactly the healthy case; the unhealthy case is simulated by lying about
    # the stat, not by trying to chown as a non-root user.
    monkeypatch.setattr(recovery_seal, "_data_dir", lambda: app_dir / "data")
    monkeypatch.setattr(recovery, "current_fingerprints",
                        lambda: {"fernet": "aaaa", "ca": "bbbb"})
    monkeypatch.setattr(recovery, "export_material",
                        lambda kinds=None: {"fernet": "k", "ca": "c"})
    return app_dir


# --------------------------------------------------------------------------
# sealing must leave the envelope readable by the account that copies it
# --------------------------------------------------------------------------

def test_seal_hands_the_envelope_to_the_tree_owner_when_run_as_root(
        sealed, monkeypatch):
    """Root wrote it; the service account has to be able to read it."""
    calls = []
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(recovery_seal, "_tree_owner", lambda: (4242, 4343))
    monkeypatch.setattr(os, "chown",
                        lambda p, u, g: calls.append((str(p), u, g)))

    recovery_seal.seal(PASS, by="test")

    assert calls, "root sealed the envelope and never handed it over"
    owned = {c[0] for c in calls}
    # Handing over the tmp file is what we WANT: os.replace keeps the inode,
    # so the envelope is already correctly owned at the instant it becomes the
    # envelope. Chowning after the replace would leave a window in which the
    # live envelope is root-owned.
    became_envelope = {str(recovery_seal.seal_path()),
                       str(recovery_seal.seal_path().with_suffix(".tmp"))}
    assert owned & became_envelope, \
        "the envelope itself was left root-owned"
    assert str(recovery_seal._seal_dir()) in owned, \
        "the directory was left root-only, so the file inside is unreachable"
    assert all(c[1:] == (4242, 4343) for c in calls), \
        "chowned to something other than the tree owner"


def test_the_envelope_is_owned_before_it_becomes_the_envelope(
        sealed, monkeypatch):
    """No window in which the live envelope is root-owned.

    A datasync firing between the replace and a later chown would copy an
    unreadable file and record a success.
    """
    order = []
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(recovery_seal, "_tree_owner", lambda: (4242, 4343))
    monkeypatch.setattr(os, "chown", lambda p, u, g: order.append(("chown", str(p))))
    real_replace = os.replace
    monkeypatch.setattr(os, "replace",
                        lambda a, b: (order.append(("replace", str(b))),
                                      real_replace(a, b))[1])

    recovery_seal.seal(PASS, by="test")

    # Anchor on the chown OF THE FILE, not on the first chown of anything:
    # the directory is handed over first, so a naive index() is satisfied by
    # the directory even when the envelope itself is chowned after publishing.
    envelope = {str(recovery_seal.seal_path()),
                str(recovery_seal.seal_path().with_suffix(".tmp"))}
    replaced = [i for i, (k, _) in enumerate(order) if k == "replace"]
    chowned = [i for i, (k, p) in enumerate(order)
               if k == "chown" and p in envelope]

    assert replaced, "the envelope was never published"
    assert chowned, "the envelope file was never handed over"
    assert min(chowned) < min(replaced), \
        "handed the envelope over only after publishing it: %r" % (order,)


def test_seal_does_not_try_to_chown_when_it_is_not_root(sealed, monkeypatch):
    """A non-root sealer already writes as the right account."""
    calls = []
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    monkeypatch.setattr(os, "chown",
                        lambda p, u, g: calls.append((str(p), u, g)))

    recovery_seal.seal(PASS, by="test")

    assert calls == [], "attempted an ownership change it cannot perform"


def test_a_refused_chown_does_not_lose_the_envelope(sealed, monkeypatch):
    """Failing to hand over must not destroy a good envelope."""
    def boom(*_a, **_k):
        raise PermissionError("nope")

    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(recovery_seal, "_tree_owner", lambda: (4242, 4343))
    monkeypatch.setattr(os, "chown", boom)

    recovery_seal.seal(PASS, by="test")          # must not raise

    assert recovery_seal.seal_path().exists()


def test_handing_it_over_does_not_widen_the_permissions(sealed, monkeypatch):
    """Reachability comes from ownership, never from loosening the mode.

    Making the envelope world-readable would 'fix' the copy mechanisms and
    hand it to every account on the box at the same time.
    """
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    recovery_seal.seal(PASS, by="test")

    mode = recovery_seal.seal_path().stat().st_mode
    assert not mode & stat_mod.S_IRGRP, "envelope became group-readable"
    assert not mode & stat_mod.S_IROTH, "envelope became world-readable"


def test_the_tree_owner_is_derived_not_hardcoded(sealed):
    """A site that runs under a different account must still work.

    The service account is 'satom' on new installs and 'fortinet' on the ones
    that adopted an existing tree; hardcoding either is how the datasync
    broke once already.
    """
    src = Path(recovery_seal.__file__).read_text()
    body = src.split("def _tree_owner", 1)[1].split("\ndef ", 1)[0]
    assert "st_uid" in body and "st_gid" in body, \
        "_tree_owner does not read the owner off the tree"
    for hardcoded in ('"satom"', "'satom'", '"fortinet"', "'fortinet'"):
        assert hardcoded not in body, \
            "_tree_owner hardcodes an account name: %s" % hardcoded


# --------------------------------------------------------------------------
# an unreachable envelope must not read as custody
# --------------------------------------------------------------------------

def _stat_lie(monkeypatch, uid, gid, mode):
    """Make the envelope and its directory stat as somebody else's."""
    real = Path.stat
    targets = {str(recovery_seal.seal_path()), str(recovery_seal._seal_dir())}

    class Fake:
        def __init__(self, st):
            self.st_uid, self.st_gid, self.st_mode = uid, gid, mode
            self.st_mtime = st.st_mtime

    def patched(self, *a, **k):
        st = real(self, *a, **k)
        return Fake(st) if str(self) in targets else st

    monkeypatch.setattr(Path, "stat", patched)


def test_an_envelope_the_copy_mechanisms_cannot_read_is_a_finding(
        sealed, monkeypatch):
    recovery_seal.seal(PASS, by="test")
    monkeypatch.setattr(recovery_seal, "_tree_owner", lambda: (1000, 1000))
    _stat_lie(monkeypatch, uid=0, gid=0, mode=0o040700)

    findings = recovery_seal.check()

    seal_findings = [f for f in findings if f["kind"] == "seal"]
    assert seal_findings, \
        "root-owned envelope reported as custody; nothing will copy it"
    assert "seal recovery" in seal_findings[0]["detail"], \
        "the finding does not say how to fix it"


def test_that_finding_is_critical_because_it_claims_a_solved_problem(
        sealed, monkeypatch):
    """A wrong 'sealed' is worse than an honest 'not sealed'."""
    recovery_seal.seal(PASS, by="test")
    monkeypatch.setattr(recovery_seal, "_tree_owner", lambda: (1000, 1000))
    _stat_lie(monkeypatch, uid=0, gid=0, mode=0o040700)

    sev = [f["severity"] for f in recovery_seal.check() if f["kind"] == "seal"]
    assert "critical" in sev, "downgraded to a warning: %r" % sev


def test_seal_state_reports_reachability_as_its_own_fact(sealed, monkeypatch):
    """Callers other than check() need to see it too."""
    recovery_seal.seal(PASS, by="test")
    monkeypatch.setattr(recovery_seal, "_tree_owner", lambda: (1000, 1000))
    _stat_lie(monkeypatch, uid=0, gid=0, mode=0o040700)

    st = recovery_seal.seal_state()
    assert st["sealed"] is True, "the envelope IS parseable; say so"
    assert st["reachable"] is False
    assert st["reach_error"], "reachability failed without saying why"


# --------------------------------------------------------------------------
# counterweights: a healthy node must stay quiet
# --------------------------------------------------------------------------

def test_an_envelope_owned_by_the_tree_owner_produces_no_finding(sealed):
    recovery_seal.seal(PASS, by="test")
    assert [f for f in recovery_seal.check() if f["kind"] == "seal"] == []


def test_reachability_is_true_on_a_healthy_node(sealed):
    recovery_seal.seal(PASS, by="test")
    st = recovery_seal.seal_state()
    assert st["reachable"] is True
    assert st["reach_error"] == ""


def test_a_group_readable_envelope_is_reachable_through_the_group(
        sealed, monkeypatch):
    """Do not fire on a setup that genuinely works.

    root:satom 0640 in a 0750 directory IS readable by the service account.
    Insisting on ownership alone would nag a site that is fine.
    """
    recovery_seal.seal(PASS, by="test")
    monkeypatch.setattr(recovery_seal, "_tree_owner", lambda: (1000, 1000))
    _stat_lie(monkeypatch, uid=0, gid=1000, mode=0o040750)

    st = recovery_seal.seal_state()
    assert st["reachable"] is True, "nagged a working group-readable setup"


def test_an_absent_envelope_does_not_report_a_reachability_problem(sealed):
    """Not sealed is its own finding; do not stack a second one on it."""
    st = recovery_seal.seal_state()
    assert st["sealed"] is False
    assert st["reach_error"] == ""


# --------------------------------------------------------------------------
# a live seal answers the escrow question -- and only a LIVE one
# --------------------------------------------------------------------------

def _seal_says(monkeypatch, **kw):
    st = {"sealed": True, "reachable": True, "stale": [],
          "fingerprints": {"fernet": "aaaa", "ca": "bbbb"},
          "kinds": ["ca", "fernet"], "at": "t", "by": "root",
          "error": "", "reach_error": "", "path": "p"}
    st.update(kw)
    monkeypatch.setattr(recovery_seal, "seal_state", lambda: st)


@pytest.fixture()
def unescrowed(monkeypatch):
    """A node holding both secrets and having escrowed neither."""
    monkeypatch.setattr(recovery, "escrow_state", lambda: {})
    monkeypatch.setattr(recovery, "current_fingerprints",
                        lambda: {"fernet": "aaaa", "ca": "bbbb"})
    monkeypatch.setattr(recovery, "holds_ca_key", lambda: True)


def test_a_live_seal_stops_the_never_exported_nagging(unescrowed, monkeypatch):
    """Sealing answers the same question, better. Keeping the warning means a
    correctly configured node can never report ok."""
    _seal_says(monkeypatch)
    assert recovery.check() == []


def test_an_unsealed_node_is_still_told_to_escrow(unescrowed, monkeypatch):
    """Counterweight: the finding must survive when nothing replaced it."""
    _seal_says(monkeypatch, sealed=False)
    kinds = {f["kind"] for f in recovery.check()}
    assert kinds == {"fernet", "ca"}


def test_an_unreachable_seal_does_not_answer_for_escrow(unescrowed, monkeypatch):
    """An envelope nothing can copy is not custody, whatever it claims."""
    _seal_says(monkeypatch, reachable=False, reach_error="root-owned")
    kinds = {f["kind"] for f in recovery.check()}
    assert kinds == {"fernet", "ca"}, \
        "an unreachable envelope silenced the escrow warning"


def test_a_stale_seal_does_not_answer_for_escrow(unescrowed, monkeypatch):
    """It holds a key that opens a different installation."""
    _seal_says(monkeypatch, stale=["fernet"])
    kinds = {f["kind"] for f in recovery.check()}
    assert "fernet" in kinds, "a stale envelope silenced the escrow warning"


def test_a_seal_holding_a_different_key_does_not_answer_for_escrow(
        unescrowed, monkeypatch):
    """Belt and braces: fingerprint mismatch even without a stale flag."""
    _seal_says(monkeypatch, fingerprints={"fernet": "zzzz", "ca": "bbbb"})
    kinds = {f["kind"] for f in recovery.check()}
    assert "fernet" in kinds
    assert "ca" not in kinds, "suppression is per-kind, not all-or-nothing"


def test_an_unreadable_seal_state_leaves_the_warning_in_place(
        unescrowed, monkeypatch):
    """Cannot tell -> stay noisy. Never the other way round."""
    def boom():
        raise RuntimeError("no app context")
    monkeypatch.setattr(recovery_seal, "seal_state", boom)
    assert {f["kind"] for f in recovery.check()} == {"fernet", "ca"}


# --------------------------------------------------------------------------
# the CLI has to be able to render its own success
# --------------------------------------------------------------------------

def _cmd_fix():
    root = Path(__file__).resolve().parents[1] / "deploy"
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    from satom_cli import cmd_fix           # noqa: PLC0415
    return cmd_fix


def test_seal_recovery_renders_its_result_without_crashing(monkeypatch):
    """It sealed, then died formatting the receipt.

    The operator saw '[FAIL] command failed' over a perfectly good envelope,
    and the only way to learn otherwise was to stat the file by hand.
    """
    cmd_fix = _cmd_fix()
    payload = {"state": {"path": "/opt/satom/data/recovery/seal.json",
                         "at": "2026-08-07T14:12:00Z", "by": "root",
                         "kinds": ["ca", "fernet"],
                         "fingerprints": {"ca": "bbbb", "fernet": "aaaa"}}}
    monkeypatch.setattr(cmd_fix, "_app_call",
                        lambda ctx, code, timeout=0: (0, json.dumps(payload), ""))
    monkeypatch.setenv(cmd_fix.SEAL_ENV, PASS)

    res = cmd_fix.seal_recovery(object(), ["--yes"])

    assert res.status == "ok", "sealed successfully and reported failure"
    rendered = "\n".join(res.render(color=False)) \
        if hasattr(res, "render") else str(res.sections)
    assert "seal.json" in rendered


def test_no_cli_command_can_crash_formatting_its_own_result():
    """The whole class, not just the two that bit.

    ``Result.rows(heading, rows)`` takes the heading FIRST, and a call that
    forgets it raises TypeError on the SUCCESS path -- after the command has
    already changed the system. It bit ``seal recovery`` (envelope written,
    '[FAIL]' printed) and it was sitting unexploded in ``reset theme``, which
    is the anti-lockout command an operator reaches for precisely when they
    cannot get into the console any other way.

    Grepping for the two known sites would not have found the third.
    """
    import ast

    root = Path(__file__).resolve().parents[1] / "deploy" / "satom_cli"
    bad = []
    for path in sorted(root.glob("*.py")):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fn = node.func
            if not (isinstance(fn, ast.Attribute) and fn.attr == "rows"):
                continue
            if len(node.args) < 2:
                bad.append("%s:%d" % (path.name, node.lineno))

    assert bad == [], (
        "Result.rows() called without a heading -- these raise TypeError on "
        "the success path, after the command has already acted: %s" % bad)


def test_a_supplied_passphrase_is_never_echoed_back(monkeypatch):
    """The receipt must not reprint what the operator already holds."""
    cmd_fix = _cmd_fix()
    payload = {"state": {"path": "p", "at": "t", "by": "root",
                         "kinds": ["fernet"], "fingerprints": {"fernet": "a"}}}
    monkeypatch.setattr(cmd_fix, "_app_call",
                        lambda ctx, code, timeout=0: (0, json.dumps(payload), ""))
    monkeypatch.setenv(cmd_fix.SEAL_ENV, PASS)

    res = cmd_fix.seal_recovery(object(), ["--yes"])

    assert PASS not in json.dumps(res.sections, default=str), \
        "the supplied passphrase came back out in the output"
