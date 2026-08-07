"""The site-rules overlay: where it lives, and what happens when it is gone.

The overlay names this estate, so it is untracked on purpose -- it must never
reach the public mirror. That decision put it outside git, and it was ALSO
outside ``data/``, which is the only thing the HA datasync carries. Three
distribution mechanisms, and the file fell between all of them: the standby ran
for days on a stale copy whose device rule matched none of the appliances
registered after it was written.

The second half is worse than the placement. ``_load_overlay`` answered
"absent", "malformed" and "one bad regex" with the same value -- an empty rule
set -- and an empty rule set reads as "nothing to redact". The comment above it
promised the opposite: that a node losing this file "fails loudly instead of
quietly redacting less". That promise was kept only by a test asserting the
file exists at collection time, which says nothing about the process serving
pages at 3am.

The permissive default IS legitimate in exactly one place: the published mirror
has no overlay and must not have one. So absence alone cannot be the signal.
``.env`` is -- a mirror is a source tree, a deployment has secrets.
"""
from __future__ import annotations

import importlib
import json
import pathlib
import re
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import app.services.doc_publication as pubdoc  # noqa: E402

OVERLAY_NAME = "publication-rules.local.json"

SAMPLE = {
    "redactions": [{"pattern": r"host-\d+", "replacement": "{node}"}],
    "forbidden": [{"name": "node", "pattern": r"host-\d+"}],
}


def _deployment(tmp_path: pathlib.Path, *, overlay=None, legacy=None,
                env: bool = True) -> pathlib.Path:
    """A stand-in application root. ``env`` marks it as a deployment."""
    (tmp_path / "data").mkdir(parents=True, exist_ok=True)
    if env:
        (tmp_path / ".env").write_text("SQLALCHEMY_DATABASE_URI=x\n")
    if overlay is not None:
        (tmp_path / "data" / OVERLAY_NAME).write_text(
            overlay if isinstance(overlay, str) else json.dumps(overlay))
    if legacy is not None:
        (tmp_path / OVERLAY_NAME).write_text(
            legacy if isinstance(legacy, str) else json.dumps(legacy))
    return tmp_path


# --------------------------------------------------------------------------
# Placement: the file has to sit where a replication mechanism can see it.
# --------------------------------------------------------------------------

def test_the_overlay_lives_under_data_where_the_datasync_can_carry_it():
    """The bug, stated as an assertion.

    ``satom-ha-datasync.sh`` rsyncs exactly ``${APP}/data/``. A config file
    beside the application, rather than inside ``data/``, is replicated by
    nothing at all.
    """
    assert pubdoc.OVERLAY_PATH.parent.name == "data", (
        "the overlay is outside data/, so the HA datasync does not carry it "
        "and the standby silently keeps whatever it had")


def test_the_datasync_excludes_do_not_swallow_the_overlay():
    """``data/`` is rsynced minus a list of volatile subdirectories.

    Every exclude is a directory. A file sitting directly in ``data/`` is
    carried -- but if someone later excludes a path that shadows it, the file
    goes back to being unreplicated with nothing to show for it.
    """
    script = pathlib.Path("/usr/local/sbin/satom-ha-datasync.sh")
    if not script.exists():
        pytest.skip("datasync script is not installed on this node")
    text = script.read_text(encoding="utf-8")
    excludes = re.findall(r"--exclude\s+'([^']+)'", text)
    assert excludes, "no --exclude entries parsed; the guard would be vacuous"
    for pat in excludes:
        assert not OVERLAY_NAME.startswith(pat.rstrip("/")), (
            f"datasync exclude {pat!r} would skip the overlay")


def test_the_overlay_is_still_ignored_by_git_in_its_new_home():
    """Moving it must not undo the reason it was untracked."""
    ignore = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    rules = {ln.strip() for ln in ignore if ln.strip() and not ln.startswith("#")}
    assert OVERLAY_NAME in rules or "/data/" in rules, (
        "the overlay would become trackable; it names the estate and must "
        "never reach the public mirror")


# --------------------------------------------------------------------------
# Loading: absent, malformed and stale are three different answers.
# --------------------------------------------------------------------------

def test_a_deployment_missing_the_overlay_refuses_to_load(tmp_path):
    """What the comment always promised and the code never did."""
    root = _deployment(tmp_path, env=True)
    with pytest.raises(pubdoc.OverlayError):
        pubdoc._load_overlay(root)


def test_a_bare_checkout_without_the_overlay_loads_the_generic_rules(tmp_path):
    """The published mirror legitimately has no overlay.

    This is why absence alone cannot be the signal, and why the fix keys on a
    deployment marker rather than simply raising whenever the file is gone.
    """
    root = _deployment(tmp_path, env=False)
    assert pubdoc._load_overlay(root) == {}


def test_malformed_json_raises_rather_than_degrading_to_no_rules(tmp_path):
    """A truncated or half-written file is never a legitimate empty overlay."""
    root = _deployment(tmp_path, overlay="{ not json", env=True)
    with pytest.raises(pubdoc.OverlayError):
        pubdoc._load_overlay(root)


def test_a_single_unusable_rule_raises_instead_of_being_skipped(tmp_path):
    """One bad regex used to cost one rule, silently.

    Skipping the entry leaves every other rule working, so the output still
    looks redacted -- while the identifier that entry covered walks straight
    through.
    """
    overlay = {"redactions": [{"pattern": "([unclosed", "replacement": "{x}"}]}
    with pytest.raises(pubdoc.OverlayError):
        pubdoc._overlay_rules("redactions", overlay)


def test_a_rule_missing_its_replacement_raises(tmp_path):
    overlay = {"redactions": [{"pattern": "host-1"}]}
    with pytest.raises(pubdoc.OverlayError):
        pubdoc._overlay_rules("redactions", overlay)


def test_a_malformed_forbidden_entry_raises(tmp_path):
    """The scanner half of the pair fails the same way and matters more:
    it is the check that aborts the build."""
    with pytest.raises(pubdoc.OverlayError):
        pubdoc._overlay_forbidden({"forbidden": [{"pattern": "([bad"}]})


def test_a_well_formed_overlay_still_loads(tmp_path):
    """The counterweight: a guard that raises on everything is not a guard."""
    root = _deployment(tmp_path, overlay=SAMPLE, env=True)
    assert pubdoc._load_overlay(root) == SAMPLE
    assert len(pubdoc._overlay_rules("redactions", SAMPLE)) == 1
    assert len(pubdoc._overlay_forbidden(SAMPLE)) == 1


# --------------------------------------------------------------------------
# Compatibility: an existing node has the file at the old path.
# --------------------------------------------------------------------------

def test_a_legacy_overlay_beside_the_application_is_still_read(tmp_path):
    """Nodes updating to this commit have the file at the repo root.

    Without the fallback, the strict loader turns a code update into a boot
    failure on every node that has not been migrated yet.
    """
    root = _deployment(tmp_path, legacy=SAMPLE, env=True)
    assert pubdoc._load_overlay(root) == SAMPLE


def test_the_replicated_copy_wins_over_the_legacy_one(tmp_path):
    """During migration both exist. The one the datasync maintains is the
    live one; the root copy is by definition the one that went stale."""
    stale = {"redactions": [{"pattern": "stale", "replacement": "{old}"}]}
    root = _deployment(tmp_path, overlay=SAMPLE, legacy=stale, env=True)
    assert pubdoc._load_overlay(root) == SAMPLE


# --------------------------------------------------------------------------
# The third mechanism: total-loss recovery.
# --------------------------------------------------------------------------

def test_the_backup_bundle_carries_the_overlay():
    """git ignores it, and the bundle packaged only pg_dump + reports + sot.

    Restoring a node from a bundle produced an installation with no site
    rules -- and, before this change, no complaint about it either.
    """
    from app.services import system_backup as sb
    names = [p.name for p in sb.config_files()]
    assert OVERLAY_NAME in names, (
        "the overlay is not in the bundle, so a restore-from-total-loss comes "
        "back without site redaction rules")


def test_restore_never_overwrites_a_live_overlay(tmp_path):
    """A restore is used to repair a node, and the node's own overlay is
    likelier to be current than the one frozen into an old bundle."""
    from app.services import system_backup as sb
    src = tmp_path / "from_bundle"
    src.mkdir()
    (src / OVERLAY_NAME).write_text(json.dumps({"redactions": []}))
    dest = tmp_path / "live"
    dest.mkdir()
    live = dest / OVERLAY_NAME
    live.write_text(json.dumps(SAMPLE))

    sb.restore_config_files(src, dest)

    assert json.loads(live.read_text()) == SAMPLE


def test_restore_places_the_overlay_when_the_node_has_none(tmp_path):
    from app.services import system_backup as sb
    src = tmp_path / "from_bundle"
    src.mkdir()
    (src / OVERLAY_NAME).write_text(json.dumps(SAMPLE))
    dest = tmp_path / "live"
    dest.mkdir()

    sb.restore_config_files(src, dest)

    assert json.loads((dest / OVERLAY_NAME).read_text()) == SAMPLE


# --------------------------------------------------------------------------
# The module still has to be importable by path from the site generator.
# --------------------------------------------------------------------------

def test_the_module_remains_stdlib_only(tmp_path):
    """``gen_site_docs.py`` loads this module BY PATH so the site can be built
    from a tree whose application code does not import. A flask/sqlalchemy
    import here would take that property away."""
    import ast
    src = (ROOT / "app" / "services" / "doc_publication.py").read_text()
    tree = ast.parse(src)
    banned = {"flask", "sqlalchemy", "app"}
    for node in ast.walk(tree):
        mods = []
        if isinstance(node, ast.Import):
            mods = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            mods = [node.module]
        for m in mods:
            assert m.split(".")[0] not in banned, (
                f"doc_publication imports {m!r}; it must stay stdlib-only so "
                "the site builds from a tree whose app code is broken")
