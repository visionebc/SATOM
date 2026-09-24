"""The compiled catalogue is an ARTEFACT, and its delivery has to be covered.

Context measured on 2026-08-10: the four `.mo` files shipped in the repo and
carried real internal identifiers -- `example.net` (x6), `10.0.0.x` addresses
(x16), `hypervisor03` (x2), `backup-server` (x8-10). That left the publisher caught
between two failures:

* Sanitising the binary (what it did) rewrites bytes INSIDE the `.mo`, shifts
  its offset table, and the published file blows up when opened. An install
  made from the public repo returned 500 on every page in es/de/fr/it, and the
  publisher reported `RESULT: OK`.
* Skipping sanitisation for binaries publishes the internal infrastructure.

The way out is not picking the lesser evil: it is that a derived artefact does
not ship. The `.po` is text, it sanitises cleanly, and the `.mo` is generated
where it is installed -- which is why these tests check BOTH delivery paths
(installer and update runner). Without them, "we no longer version the .mo"
turns into "the interface is in English and nobody knows why".
"""
from __future__ import annotations

import pathlib
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "installers" / "install-satom.sh"
UPDATER = ROOT / "deploy" / "self_update_runner.py"
SHIPPED = ("es", "de", "fr", "it")


def _tracked() -> list[str]:
    out = subprocess.run(["git", "ls-files"], cwd=ROOT,
                         capture_output=True, text=True, timeout=60)
    return out.stdout.splitlines()


def test_no_compiled_catalogue_is_tracked_by_git():
    """The concrete failure: four versioned binaries that the publisher's
    sanitiser can neither touch without breaking nor leave untouched without
    leaking."""
    tracked = [p for p in _tracked() if p.endswith(".mo")]
    assert not tracked, (
        f"compiled catalogues under version control: {tracked}. They are derived "
        "from the .po; they are generated at install time (see "
        "installers/install-satom.sh)"
    )


def test_the_source_catalogues_are_tracked():
    """The other half. Without a versioned `.po` there is nothing to derive
    from, and "we do not version the .mo" would have become losing the
    translation."""
    tracked = set(_tracked())
    for code in SHIPPED:
        rel = f"app/translations/{code}/LC_MESSAGES/messages.po"
        assert rel in tracked, f"source catalogue {rel} is missing"


def test_the_installer_compiles_the_catalogues():
    """A clean install clones the repo: without this step it starts with no
    `.mo` at all and serves the interface in English even when the profile
    asks for another language -- silently, which is how it gets discovered a
    month later."""
    body = INSTALLER.read_text(encoding="utf-8")
    assert "pybabel compile" in body, (
        "the installer does not compile the catalogues; with the .mo out of "
        "the repo that leaves every new install in English"
    )
    assert "app/translations" in body


def test_the_update_runner_compiles_the_catalogues():
    """A code update brings new `.po` files and no `.mo`."""
    body = UPDATER.read_text(encoding="utf-8")
    assert "pybabel" in body and "compile" in body, (
        "self_update_runner does not recompile the catalogues after pulling "
        "new code"
    )


def test_the_update_runner_compiles_even_without_a_pip_step():
    """Outside the ``do_pip`` block, on purpose: a code-only update also brings
    new catalogues."""
    body = UPDATER.read_text(encoding="utf-8")
    idx = body.index('pb = run([str(VENV / "pybabel")')
    before = body[:idx]
    # The last line indented by 8 spaces before the compile marks the block
    # level: if it were INSIDE `if req.get("do_pip"...)` it would have 12
    # spaces.
    line = body[idx - 8:idx]
    assert line == " " * 8, (
        "the compile step ended up nested inside do_pip; a code-only update "
        "would not recompile"
    )
    assert 'if req.get("do_pip"' in before


def test_the_compile_step_never_aborts_the_update():
    """A catalogue that fails to compile cannot take down an update: rolling
    back an update over a translation is worse than the old translation."""
    body = UPDATER.read_text(encoding="utf-8")
    idx = body.index('pb = run([str(VENV / "pybabel")')
    window = body[idx:idx + 400]
    assert "raise" not in window, (
        "the catalogue step aborts the update; it must log and carry on"
    )


@pytest.mark.parametrize("code", SHIPPED)
def test_the_catalogue_this_node_serves_is_compiled(code):
    """On a LIVE node the `.mo` has to exist even though it is not versioned.

    It is skipped -- not failed -- on a clean checkout: there its absence is
    correct, and the installer is what fixes it, covered by the test above.
    """
    mo = ROOT / "app" / "translations" / code / "LC_MESSAGES" / "messages.mo"
    po = mo.with_suffix(".po")
    if not mo.exists():
        pytest.skip("uncompiled checkout: the installer generates the .mo")
    assert mo.stat().st_mtime >= po.stat().st_mtime, (
        f"{code}: messages.mo is older than its .po -- recompile"
    )


@pytest.mark.parametrize("code", SHIPPED)
def test_the_compiled_catalogue_is_ignored_by_git(code):
    """`.gitignore` covering it is what stops it from returning to the index
    on the next ``git add -A``."""
    rel = f"app/translations/{code}/LC_MESSAGES/messages.mo"
    out = subprocess.run(["git", "check-ignore", rel], cwd=ROOT,
                         capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, f"{rel} is not covered by .gitignore"
