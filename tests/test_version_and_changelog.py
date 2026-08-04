"""Guards for the version single-source and the changelog's three surfaces.

Why these exist
---------------
The footer and Settings -> System Information each carried a literal ``v1.0``
and stayed wrong through 1.1, 1.2, 1.2.1 and 1.2.2 while the release pipeline
published the correct number to the package registry, the forge release and the
public site. Nothing failed; the number was simply never read from anywhere.

The changelog had the mirror-image problem: it was maintained carefully in the
repository and published nowhere, so the only people who could read it were the
people who already had a checkout.
"""
from __future__ import annotations

import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
VERSION_FILE = ROOT / "VERSION"
CHANGELOG = ROOT / "CHANGELOG.md"
TEMPLATES = ROOT / "app" / "templates"
SITE = ROOT / "site"

# "v1.0", "v1.2.2" — a version literal. Matched only where a version is being
# *displayed*, not in prose about a specific historical release.
VERSION_LITERAL = re.compile(r"\bv\d+\.\d+(?:\.\d+)?\b")


# --------------------------------------------------------------------------
# The version has exactly one source
# --------------------------------------------------------------------------

def test_version_file_exists_and_is_a_version():
    assert VERSION_FILE.is_file(), "VERSION is the single source and must ship"
    value = VERSION_FILE.read_text(encoding="utf-8").strip()
    assert re.fullmatch(r"\d+\.\d+(\.\d+)?", value), f"unexpected VERSION: {value!r}"


def test_app_version_module_reads_the_file():
    from app.version import app_version

    assert app_version() == VERSION_FILE.read_text(encoding="utf-8").strip()


@pytest.mark.parametrize("rel", ["base.html", "settings/index.html"])
def test_no_version_literal_in_the_templates_that_display_one(rel):
    """The footer and the System Information table must interpolate, not hardcode.

    A literal here is invisible: the page renders, the number is simply a lie.
    """
    text = (TEMPLATES / rel).read_text(encoding="utf-8")
    found = VERSION_LITERAL.findall(text)
    assert not found, (
        f"{rel} carries a version literal {found!r}; use "
        "{{ app_version }} (see app/version.py)"
    )


def test_the_rendered_settings_page_shows_the_shipped_version(app, client):
    """Rendered, against the real VERSION -- not just the template source."""
    from conftest import admin_user_id, login

    version = VERSION_FILE.read_text(encoding="utf-8").strip()
    login(client, admin_user_id(app))
    body = client.get("/settings/", follow_redirects=True).get_data(as_text=True)
    assert f"v{version}" in body, "Settings -> System Information does not show the shipped version"


def test_the_site_hero_badge_matches_the_version_file():
    """The public site's badge is stamped from VERSION, not typed by hand."""
    version = VERSION_FILE.read_text(encoding="utf-8").strip()
    index = (SITE / "index.html").read_text(encoding="utf-8")
    badges = re.findall(r'<div class="pill"><span class="dot"></span>\s*(v[0-9][^\s<·]*)', index)
    assert badges, "the hero badge disappeared — the stamper has nothing to keep current"
    for badge in badges:
        assert badge == f"v{version}", (
            f"site/index.html shows {badge} but VERSION says {version}; "
            "run: python3 deploy/stamp_site_assets.py"
        )


def test_the_asset_stamper_also_checks_the_version():
    """--check must fail on a stale badge, not only on a stale asset hash."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "stamp_site_assets", ROOT / "deploy" / "stamp_site_assets.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    stale = '<div class="pill"><span class="dot"></span> v0.1 · Production</div>'
    assert mod.stamp_version(stale, "9.9.9") != stale, \
        "stamp_version left a stale badge alone"
    assert "v9.9.9" in mod.stamp_version(stale, "9.9.9")


# --------------------------------------------------------------------------
# The changelog reaches all three surfaces
# --------------------------------------------------------------------------

# --------------------------------------------------------------------------
# SATOM-INSTALLER-VERSION
#
# The installer prints its own version in the banner. That literal sat at
# 1.3.2 while 1.3.3 and 1.3.4 shipped -- the same failure as the ``v1.0`` in
# the console footer above. A hardcoded string goes stale silently; nothing
# fails, the number is simply wrong. It is now stamped from VERSION by
# deploy/stamp_site_assets.py, so these two guards keep it that way.
# --------------------------------------------------------------------------

INSTALLER = ROOT / "installers" / "install-satom.sh"
STAMPER = ROOT / "deploy" / "stamp_site_assets.py"


def _installer_banner_version() -> str:
    for line in INSTALLER.read_text(encoding="utf-8").splitlines():
        if line.startswith('VERSION="'):
            return line.split('"')[1]
    raise AssertionError("installer has no top-level VERSION= assignment")


def test_the_installer_banner_matches_the_version_file():
    shipped = VERSION_FILE.read_text(encoding="utf-8").strip()
    assert _installer_banner_version() == shipped, (
        "installer banner says %s, VERSION says %s -- run "
        "python3 deploy/stamp_site_assets.py"
        % (_installer_banner_version(), shipped))


def test_the_stamper_actually_rewrites_the_installer_literal():
    """The guard above passes if someone hand-edits the literal once.

    This one fails unless the stamper can still do it, which is what keeps the
    number correct at the *next* release rather than at this one.
    """
    import importlib.util

    spec = importlib.util.spec_from_file_location("_stamper", STAMPER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    stale = 'VERSION="0.0.1"\necho hi\n'
    assert mod.stamp_installer(stale, "9.9.9") == 'VERSION="9.9.9"\necho hi\n'

    # It must rewrite only the first, top-level assignment -- an indented
    # VERSION= inside a function is a different variable.
    nested = 'VERSION="0.0.1"\nf() {\n  VERSION="other"\n}\n'
    out = mod.stamp_installer(nested, "9.9.9")
    assert out.startswith('VERSION="9.9.9"')
    assert 'VERSION="other"' in out


def test_changelog_lives_at_the_repository_root():
    assert CHANGELOG.is_file()
    assert "## [" in CHANGELOG.read_text(encoding="utf-8")


def test_changelog_is_printable_from_the_console():
    """The in-app catalog is gone; the console is the offline surface now."""
    import sys

    sys.path.insert(0, str(ROOT / "deploy"))
    try:
        from satom_cli import cmd_docs as mod
    finally:
        sys.path.pop(0)

    class _Ctx:
        app_dir = ROOT

    catalog = mod._doc_catalog(_Ctx())
    assert "changelog" in catalog, "the changelog vanished from the console"
    assert catalog["changelog"].is_file()
    assert mod._doc_title(catalog["changelog"])


def test_the_application_does_not_serve_the_changelog(client):
    assert client.get("/docs/CHANGELOG.md").status_code == 404


def test_changelog_is_published_on_the_public_site():
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "gen_site_docs", ROOT / "deploy" / "gen_site_docs.py")
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)

    names = {md for md, *_ in gen.PAGES}
    assert "CHANGELOG.md" in names, "the changelog is not in the site's page list"
    assert gen.source_for("CHANGELOG.md").is_file(), \
        "source_for() cannot find the changelog outside docs/"
    slugs = [slug for md, slug, *_ in gen.PAGES if md == "CHANGELOG.md"]
    grouped = {s for _, _, members in gen.GROUPS for s in members}
    assert set(slugs) <= grouped, "a published page that no hub group links to is unreachable"
    assert (SITE / "docs" / "changelog.html").is_file(), \
        "run: venv/bin/python3 deploy/gen_site_docs.py"


def test_the_published_changelog_carries_no_internal_identifiers():
    """It names hosts and backup servers freely; publication must redact them."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "gen_site_docs", ROOT / "deploy" / "gen_site_docs.py")
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)

    published = (SITE / "docs" / "changelog.html").read_text(encoding="utf-8")
    assert not gen.scan(published, "site/docs/changelog.html")
