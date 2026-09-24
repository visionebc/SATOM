"""Deploy scripts must not depend on a distro's environment.

These units run outside the application, as the service account, on any
supported distribution. They have already broken SILENTLY twice by assuming
the Debian environment:

  2026-07-27  `runuser` only works as root. When the units were moved down to
              the service account, scheduler_guard and git-publish stopped
              working and systemd kept showing SUCCESS.
  2026-08-02  `python3` does not exist on openSUSE (the binary is python3.11).
              The datasync peer discovery returned empty, the script treated
              that as "there is no peer" and exited 0: the unit green and
              data/ not replicated.

The rule: if a deploy script needs Python, it uses the application's venv.
It always exists on an installed node and has the right version.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

DEPLOY = Path(__file__).resolve().parent.parent / "deploy"

# Scripts that do NOT run on an already-installed node (there is no venv yet)
# or that are explicitly legacy. Every exemption has to be justified here.
EXEMPT = {
    "install.sh",  # legacy bootstrap: runs BEFORE the venv exists
}

SHELL_SCRIPTS = sorted(p for p in DEPLOY.glob("*.sh") if p.name not in EXEMPT)

BARE_PYTHON = re.compile(r"(?<![\w/.\-])(?:python3(?:\.\d+)?|python)\b(?![\w.\-])")


def code_lines(path: Path):
    """CODE lines: no blank lines and no comments.

    This is essential. The first version of this file did not do it and flagged
    three scripts that only mention `runuser` in a comment explaining why they
    do NOT use it. A test that matches prose proves nothing.
    """
    for n, raw in enumerate(path.read_text().splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        yield n, raw


def code_text(path: Path) -> str:
    return "\n".join(raw for _, raw in code_lines(path))


@pytest.mark.parametrize("script", SHELL_SCRIPTS, ids=lambda p: p.name)
def test_deploy_scripts_do_not_call_a_bare_python(script: Path) -> None:
    offenders = []
    for n, raw in code_lines(script):
        cleaned = raw.replace("venv/bin/python", "OKPY")
        for m in BARE_PYTHON.finditer(cleaned):
            before = cleaned[: m.start()].rstrip()
            if before and not before.endswith(("|", "(", "&&", "||", "=", ";", "$")):
                continue
            offenders.append("%s:%d: %s" % (script.name, n, raw.strip()))
    assert not offenders, (
        "A deploy script invokes a distro Python. On openSUSE "
        '/usr/bin/python3 does not exist and the failure is SILENT. Use "$APP/venv/bin/python".\n  '
        + "\n  ".join(offenders)
    )


@pytest.mark.parametrize("script", SHELL_SCRIPTS, ids=lambda p: p.name)
def test_deploy_scripts_do_not_call_runuser_without_a_root_guard(script: Path) -> None:
    """`runuser` only works as root. A script that INVOKES it has to branch
    on `id -u` or declare that it requires root."""
    text = code_text(script)
    if not re.search(r"(?<![\w/.\-])runuser\b", text):
        pytest.skip("does not invoke runuser")
    guarded = ("id -u" in text) or ("EUID" in text)
    assert guarded, (
        "%s invokes runuser without checking that it runs as root. The units "
        "were moved down to the service account on 2026-07-26 and runuser only "
        "works as root." % script.name
    )


def test_the_datasync_peer_probe_fails_loudly() -> None:
    """A probe that cannot be evaluated must NOT look like 'nothing to
    do'. That was the exact failure mode: unit green, data/ not
    replicated."""
    text = (DEPLOY / "satom-ha-datasync.sh").read_text()
    assert "PEER_RC" in text, "the peer probe's exit code is discarded"

    tail = text[text.index("PEER_RC"):]
    assert re.search(r'"\$PEER_RC"\s*-ne\s*0', tail), (
        "the peer probe's exit code is not checked"
    )
    # The block that handles the failure has to exit != 0. Look at the branch,
    # not the whole file: an `exit 1` anywhere else proves nothing.
    branch = tail[tail.index("-ne"): tail.index("-ne") + 400]
    assert "exit 1" in branch, "a peer probe failure does not exit non-zero"

    # And the legitimate case (no peer) must remain exit 0, so as not to turn
    # a standalone into a permanent alert.
    assert re.search(r'if \[ -z "\$\{PEER\}" \]', text), (
        "the distinction between 'no peer configured' and 'broken probe' was lost"
    )
