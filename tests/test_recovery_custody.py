"""Guards for recovery-material custody.

Two secrets gate recovery of an installation and no automatic mechanism
carries either: FERNET_KEY (opens every encrypted column) and the internal
CA private key (the sole issuer for replication mTLS). Putting them in a
backup bundle was rejected -- bundles are retained, mirrored to the peer and
pushed off-box over SFTP, so a bundle carrying the key that opens the SFTP
password would collapse the estate into one file.

These guards therefore protect the two properties that make the chosen
alternative worth anything:

  * a fingerprint identifies a key WITHOUT disclosing it, and
  * a restore under the wrong key SAYS SO instead of silently producing a
    database of unreadable secrets.

The counterweight tests matter as much as the positive ones: a check that
fires on a healthy node teaches operators to ignore it, which this repo has
had to unlearn three times.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from app.services import recovery


# Two well-formed, DIFFERENT Fernet keys. Literal so the assertions below can
# check the secret does not survive into a digest or a settings row.
KEY_A = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHI="
KEY_B = "ZYXWVUTSRQPONMLKJIHGFEDCBA9876543210zyxwvutsr="


# --------------------------------------------------------------------------
# fingerprint: identity without disclosure
# --------------------------------------------------------------------------

def test_a_fingerprint_does_not_disclose_the_material():
    """The whole design rests on this. A fingerprint is written into a
    manifest that travels off-box inside every bundle; if the key could be
    read back out of it, this would be strictly worse than shipping .env."""
    fpr = recovery.fingerprint(KEY_A.encode(), recovery.FERNET)
    assert fpr
    assert KEY_A not in fpr
    # No non-trivial run of the secret survives either -- catches a "digest"
    # that is really an encoding.
    for i in range(0, len(KEY_A) - 6):
        assert KEY_A[i:i + 6] not in fpr


def test_a_fingerprint_is_stable_and_distinguishes_keys():
    assert recovery.fingerprint(KEY_A.encode(), recovery.FERNET) == \
        recovery.fingerprint(KEY_A.encode(), recovery.FERNET)
    assert recovery.fingerprint(KEY_A.encode(), recovery.FERNET) != \
        recovery.fingerprint(KEY_B.encode(), recovery.FERNET)


def test_fingerprints_are_domain_separated():
    """Same bytes under two roles must not produce the same digest, or a
    digest computed for one purpose could be replayed as proof for another."""
    assert recovery.fingerprint(KEY_A.encode(), recovery.FERNET) != \
        recovery.fingerprint(KEY_A.encode(), recovery.CA)


def test_absent_material_fingerprints_to_empty_not_to_a_digest_of_nothing():
    """"" must not collide with a real key's digest, and must be falsy so
    callers can tell "no material" from "material I hashed"."""
    assert recovery.fingerprint(b"", recovery.FERNET) == ""


# --------------------------------------------------------------------------
# export: returns secrets, never writes them
# --------------------------------------------------------------------------

def test_export_returns_the_live_fernet_key(monkeypatch):
    monkeypatch.setenv("FERNET_KEY", KEY_A)
    assert recovery.export_material([recovery.FERNET])[recovery.FERNET] == KEY_A


def test_export_writes_nothing_to_disk(monkeypatch, tmp_path):
    """Choosing where a secret lands is the operator's decision. A default
    destination is how an untracked second copy gets created."""
    monkeypatch.setenv("FERNET_KEY", KEY_A)
    monkeypatch.chdir(tmp_path)
    before = set(Path(tmp_path).rglob("*"))
    recovery.export_material()
    assert set(Path(tmp_path).rglob("*")) == before


def test_export_omits_material_this_node_does_not_hold(monkeypatch, tmp_path):
    """A standby holds ca.crt but not ca.key. Exporting a placeholder would
    let an operator believe they had escrowed an issuer they never had."""
    monkeypatch.setenv("FERNET_KEY", KEY_A)
    monkeypatch.setattr(recovery, "ca_dir", lambda: tmp_path / "no-such-ca")
    assert recovery.CA not in recovery.export_material()


# --------------------------------------------------------------------------
# escrow ledger: a record, never the secret
# --------------------------------------------------------------------------

def test_the_escrow_record_never_contains_the_secret(app, monkeypatch):
    """app_settings is dumped verbatim into every bundle. A secret recorded
    here would defeat the entire reason it was kept out of the bundle."""
    monkeypatch.setenv("FERNET_KEY", KEY_A)
    with app.app_context():
        rec = recovery.record_escrow(recovery.FERNET, by="tester")
        from app.services.settings_store import get_json
        stored = get_json(recovery.ESCROW_KEY % recovery.FERNET, None)
    assert KEY_A not in repr(rec)
    assert KEY_A not in repr(stored)
    assert rec["fingerprint"] == recovery.fingerprint(KEY_A.encode(),
                                                      recovery.FERNET)


def test_record_escrow_rejects_an_unknown_kind(app):
    with app.app_context():
        with pytest.raises(ValueError):
            recovery.record_escrow("not-a-thing")


# --------------------------------------------------------------------------
# manifest: what a bundle records and what a restore concludes
# --------------------------------------------------------------------------

def test_manifest_records_a_line_per_kind_even_when_absent(monkeypatch, tmp_path):
    """An empty value and a missing line mean different things: "this node
    held no CA key" vs "this bundle predates fingerprinting". Collapsing them
    would make an old bundle indistinguishable from a standby's."""
    monkeypatch.setenv("FERNET_KEY", KEY_A)
    monkeypatch.setattr(recovery, "ca_dir", lambda: tmp_path / "no-such-ca")
    lines = recovery.manifest_lines()
    parsed = recovery.parse_manifest("\n".join(lines))
    assert parsed[recovery.FERNET] == recovery.fingerprint(KEY_A.encode(),
                                                           recovery.FERNET)
    assert recovery.CA in parsed and parsed[recovery.CA] == ""


def test_a_manifest_never_carries_the_key_itself(monkeypatch, tmp_path):
    monkeypatch.setenv("FERNET_KEY", KEY_A)
    monkeypatch.setattr(recovery, "ca_dir", lambda: tmp_path / "no-such-ca")
    assert KEY_A not in "\n".join(recovery.manifest_lines())


def test_restoring_under_a_different_key_is_reported_and_names_both(monkeypatch, tmp_path):
    """The finding this whole module exists for. Without it the operator gets
    a restored database whose every credential fails to decrypt, and nothing
    anywhere says why."""
    monkeypatch.setenv("FERNET_KEY", KEY_A)
    monkeypatch.setattr(recovery, "ca_dir", lambda: tmp_path / "no-such-ca")
    taken_under_b = "fpr_%s: %s" % (
        recovery.FERNET, recovery.fingerprint(KEY_B.encode(), recovery.FERNET))

    findings = recovery.compare_manifest(taken_under_b)

    assert [f for f in findings if f["severity"] == "critical"]
    blob = " ".join(f["detail"] for f in findings)
    assert recovery.fingerprint(KEY_B.encode(), recovery.FERNET) in blob
    assert recovery.fingerprint(KEY_A.encode(), recovery.FERNET) in blob


def test_a_matching_key_produces_no_finding(monkeypatch, tmp_path):
    """Counterweight. A check that fires on a healthy restore is a check
    operators learn to scroll past."""
    monkeypatch.setenv("FERNET_KEY", KEY_A)
    monkeypatch.setattr(recovery, "ca_dir", lambda: tmp_path / "no-such-ca")
    assert recovery.compare_manifest("\n".join(recovery.manifest_lines())) == []


def test_a_bundle_predating_fingerprints_produces_no_finding(monkeypatch, tmp_path):
    """Counterweight. Older bundles are legitimate and must stay restorable
    without a scary, meaningless warning."""
    monkeypatch.setenv("FERNET_KEY", KEY_A)
    monkeypatch.setattr(recovery, "ca_dir", lambda: tmp_path / "no-such-ca")
    assert recovery.compare_manifest("label: manual\ncreated: 20260101") == []


def test_compare_never_raises_on_a_damaged_manifest(monkeypatch, tmp_path):
    """A restore is a recovery action. A parser that throws here turns a
    recoverable outage into an unrecoverable one."""
    monkeypatch.setenv("FERNET_KEY", KEY_A)
    monkeypatch.setattr(recovery, "ca_dir", lambda: tmp_path / "no-such-ca")
    for junk in ("", "\x00\xff garbage", "fpr_fernet", ":::", "fpr_: x"):
        recovery.compare_manifest(junk)


# --------------------------------------------------------------------------
# diagnose
# --------------------------------------------------------------------------

def test_a_never_exported_key_is_a_finding(app, monkeypatch, tmp_path):
    monkeypatch.setenv("FERNET_KEY", KEY_A)
    monkeypatch.setattr(recovery, "ca_dir", lambda: tmp_path / "no-such-ca")
    with app.app_context():
        findings = recovery.check()
    assert [f for f in findings if f["kind"] == recovery.FERNET]


def test_an_exported_key_is_not_a_finding(app, monkeypatch, tmp_path):
    """Counterweight: the check must go quiet once the operator has done the
    thing it asked for, or it is just noise with extra steps."""
    monkeypatch.setenv("FERNET_KEY", KEY_A)
    monkeypatch.setattr(recovery, "ca_dir", lambda: tmp_path / "no-such-ca")
    with app.app_context():
        recovery.record_escrow(recovery.FERNET, by="tester")
        findings = recovery.check()
    assert not [f for f in findings if f["kind"] == recovery.FERNET]


def test_a_rotated_key_makes_the_old_export_a_finding(app, monkeypatch, tmp_path):
    """The copy in the operator's safe silently stopped opening the database.
    Nothing else in the product would ever notice."""
    monkeypatch.setattr(recovery, "ca_dir", lambda: tmp_path / "no-such-ca")
    with app.app_context():
        monkeypatch.setenv("FERNET_KEY", KEY_A)
        recovery.record_escrow(recovery.FERNET, by="tester")
        monkeypatch.setenv("FERNET_KEY", KEY_B)
        findings = recovery.check()
    assert [f for f in findings if f["kind"] == recovery.FERNET]


def test_a_node_without_the_ca_key_is_not_nagged_about_escrowing_it(app, monkeypatch, tmp_path):
    """Counterweight. The standby holds ca.crt only, BY DESIGN -- the primary
    is the sole issuer. Asking a standby to escrow an issuer it must not have
    is the permanent-false-positive shape this repo has removed three times."""
    monkeypatch.setenv("FERNET_KEY", KEY_A)
    monkeypatch.setattr(recovery, "ca_dir", lambda: tmp_path / "no-such-ca")
    with app.app_context():
        recovery.record_escrow(recovery.FERNET, by="tester")
        findings = recovery.check()
    assert not [f for f in findings if f["kind"] == recovery.CA]


def test_the_ca_key_holder_is_asked_to_escrow_it(app, monkeypatch, tmp_path):
    ca = tmp_path / "internal-ca"
    ca.mkdir()
    (ca / "ca.key").write_text("-" * 5 + "BEGIN PRIVATE KEY" + "-" * 5 + "\nfake\n")
    monkeypatch.setenv("FERNET_KEY", KEY_A)
    monkeypatch.setattr(recovery, "ca_dir", lambda: ca)
    with app.app_context():
        recovery.record_escrow(recovery.FERNET, by="tester")
        findings = recovery.check()
    assert [f for f in findings if f["kind"] == recovery.CA]


def test_the_ca_fingerprint_is_of_the_private_key_not_the_certificate(monkeypatch, tmp_path):
    """A certificate is public and travels freely. Fingerprinting it would
    say nothing about whether the material that can still ISSUE survived."""
    ca = tmp_path / "internal-ca"
    ca.mkdir()
    (ca / "ca.key").write_text("PRIVATE-MATERIAL")
    (ca / "ca.crt").write_text("PUBLIC-CERT")
    monkeypatch.setattr(recovery, "ca_dir", lambda: ca)
    assert recovery.ca_fingerprint() == recovery.fingerprint(b"PRIVATE-MATERIAL",
                                                             recovery.CA)

# --------------------------------------------------------------------------
# integration: the bundle seam
# --------------------------------------------------------------------------

import ast
import sys


def _fn(path, name):
    """The AST of one top-level function, comments and docstring stripped.

    Source-text assertions in this repo have matched their own explanatory
    comment twelve times. Walking the AST cannot: a comment is not a node,
    and the docstring is dropped explicitly below.
    """
    tree = ast.parse(Path(path).read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            body = list(node.body)
            if (body and isinstance(body[0], ast.Expr)
                    and isinstance(body[0].value, ast.Constant)):
                body = body[1:]
            return body
    raise AssertionError("no function %r in %s" % (name, path))


def _calls(body):
    return {n.func.attr for n in
            (x for stmt in body for x in ast.walk(stmt))
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)}


BACKUP_PY = Path(__file__).resolve().parents[1] / "app/services/system_backup.py"


def test_create_backup_records_the_fingerprints():
    """Without this the manifest carries no key identity and a restore has
    nothing to compare against -- the check downstream becomes decorative."""
    assert "manifest_lines" in _calls(_fn(BACKUP_PY, "create_backup"))


def test_restore_backup_compares_them():
    """The finding is the entire point. A bundle that records a fingerprint
    nobody reads back is a comment, not a guard."""
    assert "compare_manifest" in _calls(_fn(BACKUP_PY, "restore_backup"))


def test_the_bundle_seam_never_exports_the_material_itself():
    """system_backup must not reach for export_material(). Bundles are
    retained, mirrored to the peer and pushed off-box over SFTP; putting the
    key that opens the SFTP password inside one collapses the estate into a
    single file. This is the decision the whole module is built around."""
    src = BACKUP_PY.read_text()
    tree = ast.parse(src)
    called = {n.func.attr for n in ast.walk(tree)
              if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)}
    assert "export_material" not in called
    assert "fernet_key" not in called


# --------------------------------------------------------------------------
# the CLI check must degrade to "cannot evaluate", never to "no key"
# --------------------------------------------------------------------------

CLI = Path(__file__).resolve().parents[1] / "deploy/satom_cli"


def _cli_mod(name):
    sys.path.insert(0, str(CLI.parent))
    try:
        import importlib
        return importlib.import_module("satom_cli.%s" % name)
    finally:
        if str(CLI.parent) in sys.path:
            sys.path.remove(str(CLI.parent))


def test_the_cli_check_refuses_to_conclude_when_it_cannot_read_env(monkeypatch):
    """`.env` is 640 root:<service account>. A caller who cannot read it has
    learned NOTHING about custody -- reporting "no FERNET_KEY" there would be
    precisely the fail-open shape this whole change set exists to remove.

    Asserted behaviourally: build a context that cannot read .env, call the
    check, and require a non-zero 'cannot evaluate' rather than a finding.
    """
    mod = _cli_mod("cmd_checks")

    class Ctx:
        env_readable = False
        env = {}
        user = "nobody"
        host = "node"
        role = "primary"
        app_dir = Path("/opt/satom")

    # Stand in for the app call with a payload that WOULD produce a confident
    # verdict. Without the .env guard the check runs app code with no
    # FERNET_KEY in its environment, and the app -- which falls back to sqlite
    # when the DB URI is absent -- answers "no FERNET_KEY in this process"
    # about a node that has a perfectly good one. This double is what makes
    # the two branches distinguishable; pointing app_dir at a missing venv
    # instead just produces the same "cannot evaluate" from the other
    # fallback, and the test proves nothing.
    reached = {}

    def fake_app_json(ctx, code, timeout=60):
        reached["yes"] = True
        return ({"findings": [], "fpr": {"fernet": "deadbeefdeadbeef", "ca": ""},
                 "escrow": {"fernet": {"at": "x", "by": "y"}, "ca": None},
                 "holds_ca": False}, "")

    monkeypatch.setattr(mod, "_app_json", fake_app_json)
    r = mod.recovery(Ctx(), [])

    assert not reached, ("the check ran app code it could not supply an "
                         "environment to, and will report on a key it never saw")
    assert r.exit_code != 0
    assert "cannot evaluate" in repr(r.__dict__).lower()


def test_the_cli_check_is_registered_in_diagnose_all():
    """A check that exists but is not in the roll-up is a check nobody runs.
    `diagnose all` is the documented command for 'is this node healthy'."""
    src = (CLI / "cmd_diagnose.py").read_text()
    tree = ast.parse(src)
    pairs = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Tuple) and len(node.elts) == 2:
            k = node.elts[0]
            if isinstance(k, ast.Constant) and isinstance(k.value, str):
                pairs.add(k.value)
    assert "recovery" in pairs


# --------------------------------------------------------------------------
# every SSH channel in the app is pinned -- including the next one
# --------------------------------------------------------------------------

APP_DIR = Path(__file__).resolve().parents[1] / "app"


def _autoadd_users():
    """Files that hand paramiko a missing-host-key policy."""
    return sorted(f for f in APP_DIR.rglob("*.py")
                  if "set_missing_host_key_policy" in f.read_text())


def test_every_ssh_channel_loads_pins_before_accepting_a_key():
    """The guard that generalises.

    Three channels opened SSH here and two had NO host-key store at all:
    cert_service's autopull (which carries the node's TLS PRIVATE KEY back)
    and the ESXi shell transport (which runs commands as root on a
    hypervisor). AutoAddPolicy with nothing to compare against is not weak
    pinning -- it accepts whatever answers, every time, and never notices the
    answer changed.

    Asserting this per-file, rather than on the three we know about, is the
    point: it fails on the FOURTH channel somebody adds, which is the one
    nobody will think to check.
    """
    users = _autoadd_users()
    assert users, "no SSH channels found — this guard has gone vacuous"
    unpinned = []
    for f in users:
        tree = ast.parse(f.read_text())
        # A CALL, not the string. The first version of this guard searched the
        # text for "load_pins" and passed on a file whose only remaining
        # mention was its own now-unused import — the mutation proved it, and
        # it is the twelfth time a substring assertion in this repo has
        # matched something that was not the subject.
        called = set()
        for n in ast.walk(tree):
            if isinstance(n, ast.Call):
                fn = n.func
                if isinstance(fn, ast.Name):
                    called.add(fn.id)
                elif isinstance(fn, ast.Attribute):
                    called.add(fn.attr)
        if not called & {"load_pins", "_load_pins"}:
            unpinned.append(f.name)
    assert not unpinned, (
        "these open SSH and accept any host key with no store: %s" % unpinned)


def test_the_pinning_rule_has_exactly_one_implementation():
    """A second copy of a security rule is a second copy that rots.

    ssh_ops carried its own parser until the two unpinned channels were
    fixed; it now delegates. If this fails, someone re-inlined it.
    """
    import app.services.ssh_pinning as sp
    src = (APP_DIR / "services" / "ssh_ops.py").read_text()
    assert "HostKeyEntry" not in src, "ssh_ops re-inlined the parser"
    assert "load_pins" in src
    assert hasattr(sp, "load_pins") and hasattr(sp, "persist")


def test_an_absent_store_is_still_first_contact(tmp_path):
    """Counterweight. Pinning must not make a fresh install unusable — an
    ESXi host key legitimately changes on reinstall, and the original code
    chose AutoAdd for exactly that reason. Absent stays trusted."""
    from app.services import ssh_pinning

    class Cli:
        loaded = None

        def load_host_keys(self, p):
            self.loaded = p

    c = Cli()
    assert ssh_pinning.load_pins(c, tmp_path / "nope", RuntimeError) == 0
    assert c.loaded is None


def test_a_store_that_exists_but_cannot_be_parsed_is_refused(tmp_path):
    from app.services import ssh_pinning
    bad = tmp_path / "known_hosts"
    bad.write_text("this is not a host key line\n")

    class Cli:
        def load_host_keys(self, p):
            raise AssertionError("must not reach load_host_keys")

    with pytest.raises(RuntimeError):
        ssh_pinning.load_pins(Cli(), bad, RuntimeError)


def test_an_existing_but_empty_store_is_refused(tmp_path):
    """A truncated store is not first contact. Treating it as one silently
    re-pins to whatever answers next."""
    from app.services import ssh_pinning
    empty = tmp_path / "known_hosts"
    empty.write_text("# only a comment\n")

    class Cli:
        def load_host_keys(self, p):
            raise AssertionError("must not reach load_host_keys")

    with pytest.raises(RuntimeError):
        ssh_pinning.load_pins(Cli(), empty, RuntimeError)


# --------------------------------------------------------------------------
# a repository probe that failed is not a healthy repository
# --------------------------------------------------------------------------

def test_a_repo_git_cannot_read_is_not_reported_as_clean_and_in_sync(app, monkeypatch, tmp_path):
    """The whole chain in one assertion.

    `_git_out` collapsed "git failed" into "git said nothing", so an
    unreadable repository answered ahead=0, behind=0, dirty=False — the three
    values that mean *nothing to worry about*. `alerts._check_git` then read
    `ahead` and returned early, which made every finding below it
    structurally unreachable on exactly the repo that needed one.
    """
    from app.services import git_service as gs
    monkeypatch.setattr(gs, "_repo_root", lambda: tmp_path)  # not a repo
    with app.app_context():
        info = gs.git_info()
    assert info["unknown"] is True
    assert info["error"]


def test_a_healthy_repo_is_not_flagged(app):
    """Counterweight. This runs inside a real checkout, so a guard that
    cannot tell broken from working would fire here every time — and an
    alert that always fires is one operators mute."""
    from app.services import git_service as gs
    with app.app_context():
        assert gs.git_info()["unknown"] is False


def test_the_alert_engine_reports_an_unreadable_repo(app, monkeypatch, tmp_path):
    from app.services import git_service as gs, alerts
    monkeypatch.setattr(gs, "_repo_root", lambda: tmp_path)
    with app.app_context():
        keys = [f["key"] for f in alerts._check_git()]
    assert "git.unreadable" in keys


def test_the_alert_engine_is_quiet_on_a_healthy_repo(app):
    """Counterweight for the alert half."""
    from app.services import alerts
    with app.app_context():
        assert "git.unreadable" not in [f["key"] for f in alerts._check_git()]


def test_safety_decisions_do_not_use_the_defaulting_helper():
    """`_git_out` returns a DEFAULT on failure, which is indistinguishable
    from an answer. Anything deciding whether the repo is clean, ahead or
    behind must use `_git_try`, which reports whether git answered at all."""
    import app.services.git_service as gs
    body = _fn(Path(gs.__file__), "git_info")
    calls = _calls(body) | {n.func.id for n in
                            (x for s in body for x in ast.walk(s))
                            if isinstance(n, ast.Call)
                            and isinstance(n.func, ast.Name)}
    assert "_git_try" in calls, "git_info stopped distinguishing failure"
