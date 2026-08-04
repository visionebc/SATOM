"""Guards for the two defects found installing v1.3.2 on blank openSUSE.

Both were found by INSTALLING, not by reading. See docs/safeguards.md 10b.
"""
import pathlib
import re
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "installers" / "install-satom.sh"
sys.path.insert(0, str(ROOT / "deploy"))


# --------------------------------------------------------------------------
# A. The installer must not reload nginx it just started.
# --------------------------------------------------------------------------
def _logical_line(text, needle):
    """The full shell logical line containing `needle`, following `\\` joins."""
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if needle in line:
            out = [line]
            while out[-1].rstrip().endswith("\\") and i + len(out) < len(lines):
                out.append(lines[i + len(out)])
            return "\n".join(out)
    return ""


def _executed_lines(text):
    """Lines that are actually run, not prose/sudoers templates."""
    out = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        out.append(stripped)
    return out


def test_installer_never_executes_a_bare_systemctl_reload_nginx():
    """openSUSE ships nginx.service as Type=simple with

        ExecStart=/usr/sbin/nginx -g "daemon off;"
        ExecReload=/bin/kill -s HUP $MAINPID

    systemd calls the unit started the instant it exec()s, BEFORE nginx has
    written /run/nginx.pid. A `systemctl reload` issued right after the start
    therefore resolves $MAINPID to nothing, `kill` exits 2, and systemd tears
    down the whole service -- on an installation that had completed correctly.
    Debian and RHEL use forking units with PIDFile, so systemd waits for the
    pid and the race is invisible there. A run that passes proves nothing.
    """
    offenders = [
        ln for ln in _executed_lines(INSTALLER.read_text())
        if re.match(r"^systemctl\s+reload\s+nginx\b", ln)
    ]
    assert offenders == [], (
        "installer executes `systemctl reload nginx`: %r" % offenders
    )


def test_installer_start_of_nginx_is_guarded_and_waits_for_readiness():
    text = INSTALLER.read_text()
    assert "SATOM-NGINX-START" in text, "readiness guard marker is gone"

    # the start itself must not be able to fail silently
    # Scope the assertion to the START command's own LOGICAL line. A fixed
    # character window is not good enough: it reaches the `|| die` belonging to
    # the readiness loop below, so dropping the start's guard would still pass.
    # (Mutation M2 caught exactly that -- the bug was in this test.)
    logical = _logical_line(text, "systemctl enable --now nginx")
    assert logical, "installer no longer starts nginx"
    assert "|| die" in logical, (
        "the nginx start is unguarded -- a failed start would sail past: %r"
        % logical
    )

    # a non-empty pid file is the precondition that makes any LATER
    # `systemctl reload nginx` (cert_service does one via sudoers) safe.
    assert "[ -s /run/nginx.pid ]" in text, (
        "readiness no longer requires a populated pid file"
    )
    assert "sleep 1" in text, "no bounded wait loop"


# --------------------------------------------------------------------------
# B. A standalone install has no peer channel, so it must not be graded.
# --------------------------------------------------------------------------
@pytest.fixture()
def nginx_probes():
    from satom_cli.cmd_checks import nginx_probes as fn
    return fn


def test_standalone_does_not_grade_the_peer_channel(nginx_probes):
    """Every fresh single-node install used to open with `[warn] nginx`, whose
    only complaint was that :8443 -- the node-to-node channel a standalone
    deliberately does not have -- did not answer. Same chronic false positive
    already removed from `get system health` for the datasync timer that is
    inert by design on a primary. A check that always complains gets skipped.
    """
    probes = nginx_probes("standalone")
    assert len(probes) == 1
    assert all(":8443" not in url for _, url in probes)


@pytest.mark.parametrize("role", ["primary", "standby", "unknown"])
def test_every_other_role_still_grades_the_peer_channel(nginx_probes, role):
    """Silencing standalone must not silence a real cluster: on a pair, a dead
    :8443 means the peers cannot probe each other.
    """
    probes = nginx_probes(role)
    assert len(probes) == 2
    assert any(":8443" in url for _, url in probes)


def test_the_app_probe_is_never_dropped(nginx_probes):
    for role in ("standalone", "primary", "standby", "unknown"):
        assert any(url.endswith("127.0.0.1/healthz")
                   for _, url in nginx_probes(role)), role
