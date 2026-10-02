"""Every script under installers/ is run directly by operators (`./installers/x.sh`)
from a fresh clone, so git must record it as executable.

installers/build-update-package.sh was committed as 100644 on 2026-08-04 and
stayed that way through four releases: `./installers/build-update-package.sh`
on a GitHub clone failed with "Permission denied". The on-disk mode does not
travel through git; only the index mode does, so this reads the index.
"""
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent


def _index_modes():
    if shutil.which("git") is None or not (REPO / ".git").exists():
        pytest.skip("not a git checkout")
    out = subprocess.run(
        ["git", "-C", str(REPO), "ls-files", "-s", "--", "installers/*.sh"],
        capture_output=True, text=True, check=True).stdout
    modes = {}
    for line in out.splitlines():
        meta, path = line.split("\t", 1)
        modes[path] = meta.split()[0]
    return modes


def test_installer_scripts_are_tracked():
    assert "installers/build-update-package.sh" in _index_modes()


def test_every_installer_script_is_executable_in_git():
    bad = sorted(p for p, m in _index_modes().items() if m != "100755")
    assert not bad, (
        "installers committed without the exec bit (fix with "
        "`git update-index --chmod=+x <file>`): %s" % bad)
