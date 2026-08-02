"""The manual is reachable from the sign-in screen — and cannot leak.

Two defects motivated these guards (2026-08-02):

1. **The sign-in page linked to the API manual and nothing else.** An operator
   who cannot get in is exactly the person who needs the installation guide,
   the operator-console reference and the recovery runbooks, and on an isolated
   management network there is no other copy to reach.

2. **``/docs/api`` was unauthenticated and served ``docs/api_v1.md`` verbatim** —
   including a management hostname and an RFC1918 address — to anyone who could
   load the login page. The redact-then-scan pipeline that guards the public web
   site lived inside ``deploy/gen_site_docs.py``, where the application could not
   reuse it. A second copy is the copy that rots; the registry and the redaction
   table now live in ``app/services/doc_publication.py`` and BOTH published
   surfaces import them.

The load-bearing test is :func:`test_the_raw_source_really_does_carry_an_identifier`.
Without it, narrowing ``redact()`` and ``scan()`` together leaves a
redact-then-scan round trip self-consistent and green while publishing the
identifier — the same false-negative that a mutation run reported as "does not
bite" earlier in this repo's history.
"""
from __future__ import annotations

import importlib.util
import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]

from app.services import doc_publication as pubdoc  # noqa: E402

AUTH_TEMPLATES = ("login.html", "forgot.html", "reset.html", "two_factor.html")
CURATED_SITE_PAGES = ("index.html", "features.html", "architecture.html",
                      "safeguards.html", "install.html")
SLUGS = [entry[1] for entry in pubdoc.PUBLIC_DOCS]


def _generator():
    spec = importlib.util.spec_from_file_location(
        "gsd_under_test", ROOT / "deploy" / "gen_site_docs.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# One registry, two surfaces
# ---------------------------------------------------------------------------

def test_the_site_generator_uses_the_shared_registry_not_a_copy():
    """Structural, not just equal-valued.

    Two lists can be equal today and drift tomorrow, so equality alone would
    pass on the very day someone re-pastes the registry into the generator.
    The generator loads the shared module by PATH (it must keep working on a
    tree whose ``app`` package does not import), so object identity is not
    available either -- assert instead that the generator DEFINES none of it.
    """
    import ast

    gsd = _generator()
    assert gsd.PAGES == pubdoc.PUBLIC_DOCS
    assert gsd.GROUPS == pubdoc.GROUPS
    assert gsd.REDACTIONS == pubdoc.REDACTIONS
    assert gsd.FORBIDDEN == pubdoc.FORBIDDEN

    tree = ast.parse((ROOT / "deploy" / "gen_site_docs.py").read_text(encoding="utf-8"))
    owned = {"PAGES", "GROUPS", "REDACTIONS", "FORBIDDEN", "MD_EXTENSIONS"}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            assert node.name not in {"redact", "scan", "source_for"}, \
                f"{node.name}() is defined twice -- it belongs to doc_publication"
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for t in targets:
                if isinstance(t, ast.Name) and t.id in owned:
                    assert isinstance(node.value, ast.Attribute), (
                        f"{t.id} is re-declared in the generator instead of "
                        "being taken from the shared registry")


def test_every_group_slug_resolves_and_every_doc_is_grouped():
    grouped = {d["slug"] for g in pubdoc.grouped() for d in g["docs"]}
    assert grouped == set(SLUGS), "a published doc is unreachable from the hub"


def test_the_shared_module_imports_nothing_from_the_application():
    """The site build has to survive a tree whose app code does not compile."""
    src = (ROOT / "app" / "services" / "doc_publication.py").read_text(encoding="utf-8")
    tree = __import__("ast").parse(src)
    for node in __import__("ast").walk(tree):
        if isinstance(node, __import__("ast").ImportFrom):
            assert not (node.module or "").startswith(("app", "flask")), node.module
        if isinstance(node, __import__("ast").Import):
            for a in node.names:
                assert not a.name.startswith(("app", "flask")), a.name


# ---------------------------------------------------------------------------
# The public surface renders, and cannot leak
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("slug", SLUGS)
def test_every_published_document_renders_without_a_session(client, slug):
    r = client.get(f"/docs/public/{slug}")
    assert r.status_code == 200, slug
    assert len(r.get_data()) > 500


@pytest.mark.parametrize("slug", SLUGS)
def test_no_published_document_carries_an_internal_identifier(client, slug):
    body = client.get(f"/docs/public/{slug}").get_data(as_text=True)
    for name, pattern in pubdoc.FORBIDDEN:
        m = pattern.search(body)
        assert m is None, f"{slug}: {name}: {m.group(0)!r}"


def test_the_hub_and_the_legacy_api_url_are_public_and_clean(client):
    for path in ("/docs/public", "/docs/api"):
        r = client.get(path)
        assert r.status_code == 200, path
        body = r.get_data(as_text=True)
        for name, pattern in pubdoc.FORBIDDEN:
            assert pattern.search(body) is None, f"{path}: {name}"


def test_the_raw_source_really_does_carry_an_identifier():
    """Redaction is load-bearing, not decorative.

    ``docs/api_v1.md`` is the document the sign-in page has always linked to.
    If this ever stops finding an identifier, the leak tests above have become
    vacuous and someone must re-check them against a document that does.
    """
    raw = pubdoc.source_for("api_v1.md").read_text(encoding="utf-8")
    hits = [n for n, p in pubdoc.FORBIDDEN if p.search(raw)]
    assert hits, "api_v1.md no longer carries an internal identifier"
    assert not pubdoc.scan(pubdoc.redact(raw), "api_v1.md")


def test_the_scanner_matches_each_forbidden_class():
    samples = {
        "rfc1918 address": "reach it at 192.0.2.248 over TLS",
        "internal hostname": "browse https://node-a.example.net/healthz",
        "hypervisor name": "the container lives on hypervisor06 today",
        "node name": "hostnames are satom-node prefixed",
        "backup server name": "pushes land on backup-server nightly",
        "device instance name": "harvested from fortiweb08 hourly",
        "personal e-mail": "alerts go to opensource@visionebc.com daily",
    }
    for name, _pattern in pubdoc.FORBIDDEN:
        assert name in samples, f"no sample for {name}"
    for name, line in samples.items():
        assert any(name in f for f in pubdoc.scan(line, "x")), name
        assert not pubdoc.scan(pubdoc.redact(line), "x"), name


def test_product_identifiers_are_not_over_redacted():
    """ADOM keys and product URL segments are labels, not an inventory."""
    keep = "the /fadc/api/ console covers fortiweb, fadc and faz objects"
    assert pubdoc.redact(keep) == keep


def test_publication_is_fail_closed(client, monkeypatch):
    """A document that survives redaction is not served at all."""
    monkeypatch.setattr(pubdoc, "redact", lambda text: text)
    assert client.get("/docs/public/api").status_code == 404
    assert client.get("/docs/api").status_code == 404


@pytest.mark.parametrize("slug", ["nope", "engineering.md", "..%2f..%2fsecret"])
def test_unknown_slugs_are_refused(client, slug):
    assert client.get(f"/docs/public/{slug}").status_code == 404


def test_the_authenticated_manual_still_requires_a_session(client):
    for path in ("/docs/", "/docs/overview.md"):
        assert client.get(path).status_code in (302, 401), path


# ---------------------------------------------------------------------------
# The links themselves
# ---------------------------------------------------------------------------

def test_the_sign_in_page_links_to_both_manuals(client):
    body = client.get("/auth/login").get_data(as_text=True)
    assert "/docs/public" in body, "no link to the documentation"
    assert "/docs/api" in body, "no link to the API manual"


@pytest.mark.parametrize("name", AUTH_TEMPLATES)
def test_auth_pages_do_not_need_public_internet_to_lay_themselves_out(name):
    src = (ROOT / "app" / "templates" / "auth" / name).read_text(encoding="utf-8")
    assert "cdn.jsdelivr.net/npm/bootstrap@" not in src, name
    assert "vendor/bootstrap/bootstrap.min.css" in src, name


def test_the_public_docs_shell_is_local_and_theme_aware():
    src = (ROOT / "app" / "templates" / "docs" / "_public_base.html").read_text(encoding="utf-8")
    assert "cdn.jsdelivr.net/npm/bootstrap@" not in src
    assert "vendor/bootstrap/bootstrap.min.css" in src
    assert "theme_css" in src and "theme_logo_url" in src
    # The pre-rename "FM" placeholder box lived here long after the rename.
    assert '<span class="logo">FM</span>' not in src


# ---------------------------------------------------------------------------
# The static site carries the API manual as a destination, not a buried card
# ---------------------------------------------------------------------------

def test_the_site_nav_offers_the_api_manual():
    nav = dict(_generator().NAV)
    assert nav.get("docs/api.html") == "API"


@pytest.mark.parametrize("page", CURATED_SITE_PAGES)
def test_curated_pages_carry_the_same_nav_as_the_generated_ones(page):
    """The five hand-written pages had already drifted from the generated
    chrome — index.html's footer had lost "Docs" entirely."""
    html = (ROOT / "site" / page).read_text(encoding="utf-8")
    nav_block = re.search(r'<div class="nav-links">(.*?)</div>', html, re.S)
    foot_block = re.search(r'<div class="flinks">(.*?)</div>', html, re.S)
    assert nav_block and foot_block, page
    for href, label in _generator().NAV:
        assert f'href="{href}"' in nav_block.group(1), f"{page} nav missing {href}"
        assert f'href="{href}"' in foot_block.group(1), f"{page} footer missing {href}"
