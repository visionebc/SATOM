"""An offline bundle has to carry everything the installer will ask for.

The failure this guards against already shipped twice:

* **1.1 and earlier** — `sudo` was in the installer's required list but in no
  builder's package list. On a minimal image with no network the preflight said
  OK and the install died at step 6, *after* creating the service account and
  chowning the tree. `openssh-*` was missing too, so a cluster install had no
  replication channel.
* **1.1 RHEL** — the ACME client sat inside the wrong branch of the builder, so
  the bundle documented as shipping ACME did not contain it.

Both are the same shape: two lists that must agree, kept in two files, compared
by nobody. These tests compare them.

They are static: they read the shell sources. Actually building a bundle needs
a network and a container per distribution family, which is a release step, not
a unit test — but a bundle that cannot possibly satisfy the installer is worth
catching before anyone spends twenty minutes building it.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
INSTALLERS = ROOT / "installers"
INSTALLER = INSTALLERS / "install-satom.sh"

# builder -> (package-manager key in the installer, bundle directory, tarball tag)
BUILDERS = {
    "build-offline-bundle.sh": ("apt", "debs", "debian12-amd64"),
    "build-offline-bundle-rhel.sh": ("dnf|yum", "rpms", "rhel9-x86_64"),
    "build-offline-bundle-suse.sh": ("zypper", "rpms-suse", "suse15-x86_64"),
}


def _array(text: str, name: str) -> list[str]:
    """Read a `NAME=(a b c)` shell array, tolerating line continuations."""
    m = re.search(rf"^{re.escape(name)}=\((.*?)\)", text, re.S | re.M)
    assert m, f"array {name}= not found"
    body = re.sub(r"#.*", "", m.group(1))
    return [w for w in body.split() if w]


def _installer_case_array(name: str, mgr_key: str) -> list[str]:
    """Read one branch of `case "$PKG_MGR" in ... NAME=(...) ;;`."""
    text = INSTALLER.read_text(encoding="utf-8")
    pat = rf"^\s*{re.escape(mgr_key)}\)\s*{re.escape(name)}=\(([^)]*)\)"
    m = re.search(pat, text, re.M)
    assert m, f"{name} branch for {mgr_key} not found"
    return [w for w in m.group(1).split() if w]


@pytest.mark.parametrize("builder", sorted(BUILDERS))
def test_every_builder_exists_and_parses(builder):
    p = INSTALLERS / builder
    assert p.is_file(), builder
    r = subprocess.run(["bash", "-n", str(p)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


@pytest.mark.parametrize("builder", sorted(BUILDERS))
def test_a_bundle_carries_every_package_the_installer_requires(builder):
    mgr, _dirname, _tag = BUILDERS[builder]
    src = (INSTALLERS / builder).read_text(encoding="utf-8")
    shipped = set(_array(src, "PKGS"))
    required = set(_installer_case_array("REQUIRED_PKGS", mgr))
    missing = required - shipped
    assert not missing, (
        f"{builder} does not ship {sorted(missing)} — an offline install would "
        "die mid-way, after the service account already exists")


@pytest.mark.parametrize("builder", sorted(BUILDERS))
def test_a_bundle_carries_the_cluster_ssh_packages(builder):
    """Cluster mode replicates data/ over rsync-on-SSH. No sshd, no standby."""
    mgr, _dirname, _tag = BUILDERS[builder]
    shipped = set(_array((INSTALLERS / builder).read_text(encoding="utf-8"), "PKGS"))
    ssh = set(_installer_case_array("SSH_PKGS", mgr))
    assert ssh <= shipped, f"{builder} is missing {sorted(ssh - shipped)}"


@pytest.mark.parametrize("builder", sorted(BUILDERS))
def test_every_builder_ships_the_acme_client(builder):
    """1.1's RHEL bundle had lego inside the wrong branch and shipped without it."""
    src = (INSTALLERS / builder).read_text(encoding="utf-8")
    assert "bundle/lego" in src, f"{builder} does not stage the ACME client"
    assert "sha256sum" in src and "mismatch" in src, \
        f"{builder} does not verify lego's checksum on the machine that has network"


@pytest.mark.parametrize("builder", sorted(BUILDERS))
def test_every_builder_emits_its_own_tarball_name_and_a_checksum(builder):
    _mgr, _dirname, tag = BUILDERS[builder]
    src = (INSTALLERS / builder).read_text(encoding="utf-8")
    assert tag in src, f"{builder} does not name its family in the tarball"
    assert "sha256sum \"$(basename \"$TARBALL\")\"" in src, \
        f"{builder} writes no .sha256 beside the tarball"


def test_the_installer_gates_each_bundle_on_its_own_family():
    """A bundle for the wrong family must be refused BEFORE anything is touched.

    Both RPM bundles exist and are not interchangeable: different package
    names, different base library versions, and zypper and dnf do not read
    repositories the same way. If either directory were accepted by both
    managers the failure would surface as a dependency resolution error
    halfway through an install.
    """
    text = INSTALLER.read_text(encoding="utf-8")
    for _builder, (mgr, dirname, _tag) in BUILDERS.items():
        m = re.search(rf'\[ -d "\$BUNDLE_DIR/{re.escape(dirname)}" \]', text)
        assert m, f"the installer never looks for bundle/{dirname}"
        window = text[m.start():m.start() + 900]
        assert mgr.split("|")[0] in window, \
            f"bundle/{dirname} is not gated on the {mgr} family"
        assert "die " in window, f"bundle/{dirname} has no refusal path"


def test_the_bundle_probe_knows_every_bundle_layout():
    """pf_bundle_has answers "will the bundle supply this?" in the preflight.

    A layout it does not know reports "not in the bundle" for packages that
    are, and the preflight blocks an install that would have worked.
    """
    text = INSTALLER.read_text(encoding="utf-8")
    m = re.search(r"pf_bundle_has\(\)\s*\{(.*?)\n\}", text, re.S)
    assert m, "pf_bundle_has() not found"
    body = m.group(1)
    for _builder, (_mgr, dirname, _tag) in BUILDERS.items():
        assert f"/{dirname}/" in body, f"pf_bundle_has cannot see bundle/{dirname}"


def test_the_suse_path_never_registers_a_repository_on_the_target():
    """Installing must not leave state nobody asked for.

    zypper gets a repository directory of its own; the alternative (`addrepo`)
    would leave the bundle registered on the machine after the install, so the
    next `zypper update` would try to resolve against a directory that may no
    longer exist.
    """
    text = INSTALLER.read_text(encoding="utf-8")
    m = re.search(r'elif \[ -d "\$BUNDLE_DIR/rpms-suse" \]; then(.*?)\n        else', text, re.S)
    assert m, "the SUSE install branch is missing"
    branch = m.group(1)
    assert "--reposd-dir" in branch
    assert "addrepo" not in branch, "the SUSE branch registers a repository on the target"
    assert "--no-gpg-checks" in branch, "a local bundle has no signing key to check against"


# --- SATOM-GIT-PKG -----------------------------------------------------------
# 1.3.3 and earlier: `git` was never in REQUIRED_PKGS and never in a builder's
# PKGS. The ONLINE path installed it as a side effect of cloning the repo, so
# only air-gapped installs were affected: satom-git-publish.service failed every
# hour and backup copy 3 (the reports/ SoT versioned in git) silently did not
# exist. The generic test above only proves the builders agree with
# REQUIRED_PKGS — dropping git from BOTH would keep it green. This one names it.

_FAMILIES = ("apt", "dnf|yum", "zypper", "pacman")


@pytest.mark.parametrize("mgr", _FAMILIES)
def test_git_is_required_on_every_family(mgr):
    assert "git" in _installer_case_array("REQUIRED_PKGS", mgr), (
        f"{mgr}: git is not a required package. satom-git-publish, the nightly "
        "git bundle and the self-update runner all shell out to it."
    )


@pytest.mark.parametrize("builder", sorted(BUILDERS))
def test_every_offline_bundle_carries_git(builder):
    shipped = _array((INSTALLERS / builder).read_text(encoding="utf-8"), "PKGS")
    assert "git" in shipped, (
        f"{builder} does not package git — an air-gapped install would lose "
        "backup copy 3 and fail satom-git-publish hourly, with no other symptom"
    )


def test_the_cli_names_a_missing_git_binary():
    """Reporting "repository unusable" points the operator at the wrong thing."""
    src = (ROOT / "deploy/satom_cli/cmd_checks.py").read_text(encoding="utf-8")
    assert 'shutil.which("git")' in src, \
        "diagnose git no longer detects an absent git binary"
    assert "not installed" in src
