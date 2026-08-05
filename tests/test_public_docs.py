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

import leak_samples

ROOT = pathlib.Path(__file__).resolve().parents[1]

from app.services import doc_publication as pubdoc  # noqa: E402

AUTH_TEMPLATES = ("login.html", "forgot.html", "reset.html", "two_factor.html")
CURATED_SITE_PAGES = ("index.html", "features.html", "architecture.html",
                      "safeguards.html", "install.html")
SLUGS = [entry[1] for entry in pubdoc.PUBLIC_DOCS]


def _cli_docs_module():
    """Load the console's doc reader.

    By package, not by file path: ``cmd_docs`` uses relative imports, and a
    ``spec_from_file_location`` load of a package member raises ImportError.
    """
    import sys
    sys.path.insert(0, str(ROOT / "deploy"))
    try:
        from satom_cli import cmd_docs
    finally:
        sys.path.pop(0)
    return cmd_docs


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
# The application serves NO manual (2026-08-02)
#
# It used to serve three: /docs (session), /docs/public and /docs/api. That was
# a second rendered copy of the same Markdown living on every management node,
# and the reason the API route once leaked -- the redaction pipeline lived in
# the site generator, so the application grew its own unguarded route instead
# of reusing it. There is now ONE published copy, on the public site, and the
# sign-in page links straight to it.
#
# The leak guards did not disappear with the routes; they moved onto the
# generated HTML, which is the artefact that actually gets published.
# ---------------------------------------------------------------------------

REMOVED_ROUTES = ("/docs/", "/docs", "/docs/public", "/docs/api",
                  "/docs/public/api", "/docs/overview.md")


@pytest.mark.parametrize("path", REMOVED_ROUTES)
def test_the_application_serves_no_manual(client, path):
    """404, not a redirect to the sign-in page.

    A 302 would mean the route still exists behind ``@login_required`` -- i.e.
    the second copy is still there, one decorator away from being public again.
    """
    assert client.get(path).status_code == 404, path


def test_no_template_links_to_an_in_app_manual():
    """The blueprint is gone, so a surviving url_for('docs.*') is a 500."""
    offenders = []
    for tpl in (ROOT / "app" / "templates").rglob("*.html"):
        body = tpl.read_text(encoding="utf-8", errors="replace")
        if re.search(r"""url_for\(\s*['"]docs\.""", body):
            offenders.append(str(tpl.relative_to(ROOT)))
    assert not offenders, f"link to a removed blueprint: {offenders}"


def test_the_view_module_and_its_templates_are_gone():
    assert not (ROOT / "app" / "views" / "docs.py").exists()
    assert not (ROOT / "app" / "templates" / "docs").exists()


@pytest.mark.parametrize("slug", SLUGS)
def test_every_published_document_is_generated(slug):
    page = ROOT / "site" / "docs" / f"{slug}.html"
    assert page.is_file(), f"{slug}: run deploy/gen_site_docs.py"
    assert len(page.read_bytes()) > 500, slug


@pytest.mark.parametrize("slug", SLUGS)
def test_no_published_document_carries_an_internal_identifier(slug):
    body = (ROOT / "site" / "docs" / f"{slug}.html").read_text(encoding="utf-8")
    for name, pattern in pubdoc.FORBIDDEN:
        m = pattern.search(body)
        assert m is None, f"{slug}: {name}: {m.group(0)!r}"


def test_the_hub_is_generated_and_clean():
    body = (ROOT / "site" / "docs.html").read_text(encoding="utf-8")
    for name, pattern in pubdoc.FORBIDDEN:
        assert pattern.search(body) is None, name


@leak_samples.requires_corpus
def test_the_raw_source_really_does_carry_an_identifier():
    """Redaction is load-bearing, not decorative.

    ``docs/api_v1.md`` is the document the sign-in page has always linked to.
    If this ever stops finding an identifier, the leak tests above have become
    vacuous and someone must re-check them against a document that does.
    """
    doc = leak_samples.SAMPLES["source_doc_with_identifier"]
    raw = pubdoc.source_for(doc).read_text(encoding="utf-8")
    hits = [n for n, p in pubdoc.FORBIDDEN if p.search(raw)]
    assert hits, f"{doc} no longer carries an internal identifier"
    assert not pubdoc.scan(pubdoc.redact(raw), doc)


@leak_samples.requires_corpus
def test_the_scanner_matches_each_forbidden_class():
    samples = leak_samples.SAMPLES["by_class"]
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


# ---------------------------------------------------------------------------
# The links themselves
# ---------------------------------------------------------------------------

def test_the_sign_in_page_links_to_both_manuals(client):
    body = client.get("/auth/login").get_data(as_text=True)
    assert pubdoc.site_url() in body, "no link to the published manual"
    assert pubdoc.site_url("api") in body, "no link to the published API manual"
    assert "/docs/public" not in body, "still linking at a route that is gone"


def test_the_published_address_has_exactly_one_definition():
    """A literal in two templates is two chances to move the site and leave
    one of them on a 404."""
    offenders = []
    for tpl in (ROOT / "app" / "templates").rglob("*.html"):
        if pubdoc.SITE_BASE in tpl.read_text(encoding="utf-8", errors="replace"):
            offenders.append(str(tpl.relative_to(ROOT)))
    assert not offenders, f"hardcoded site address, use docs_url(): {offenders}"


def test_the_sidebar_documentation_entry_leaves_the_application():
    body = (ROOT / "app" / "templates" / "base.html").read_text(encoding="utf-8")
    assert "docs_url()" in body, "the sidebar lost its Documentation entry"
    assert 'url_for(\'docs.index\')' not in body


def test_the_console_can_print_every_document():
    """The offline half of the trade.

    Removing the in-app manual is only safe because the console keeps one. A
    management network has no route to the public site, so if this catalogue
    ever stops covering docs/, the isolated node has no manual at all.
    """
    mod = _cli_docs_module()

    class _Ctx:
        app_dir = ROOT

    catalog = mod._doc_catalog(_Ctx())
    expected = {p.stem.lower().replace("_", "-") for p in (ROOT / "docs").glob("*.md")}
    assert expected <= set(catalog), \
        f"the console cannot print: {sorted(expected - set(catalog))}"
    assert "changelog" in catalog
    for name in catalog:
        assert mod._doc_title(catalog[name])


@pytest.mark.parametrize("name", AUTH_TEMPLATES)
def test_auth_pages_do_not_need_public_internet_to_lay_themselves_out(name):
    src = (ROOT / "app" / "templates" / "auth" / name).read_text(encoding="utf-8")
    assert "cdn.jsdelivr.net/npm/bootstrap@" not in src, name
    assert "vendor/bootstrap/bootstrap.min.css" in src, name


def test_the_generated_site_shell_carries_no_dead_placeholder():
    """The pre-rename "FM" box and the CDN dependency lived in the deleted
    in-app shell. The generated shell inherits the same rules."""
    body = (ROOT / "site" / "docs.html").read_text(encoding="utf-8")
    assert '<span class="logo">FM</span>' not in body
    assert "cdn.jsdelivr.net/npm/bootstrap@" not in body


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


# ---------------------------------------------------------------------------
# Cross-references (2026-08-03)
#
# The manual links Markdown to Markdown -- correct in the repository, dead
# everywhere it is published: the artefact is `cli.html` and nothing serves the
# `.md`. Seventy-one such links across ten pages rendered perfectly, sat on
# pages that returned 200, and every one of them 404ed when FOLLOWED. Only
# requesting a target finds this class of defect.
#
# Two halves, both required. test_no_published_page_offers_a_markdown_link
# alone is satisfied by a relink() that deletes every link; the positive test
# pins that real cross-references survive and point somewhere that exists.
# ---------------------------------------------------------------------------
SITE_DOC_PAGES = sorted((ROOT / "site" / "docs").glob("*.html")) + sorted(
    (ROOT / "site" / "releases").glob("*.html"))


@pytest.mark.parametrize("page", SITE_DOC_PAGES, ids=lambda p: p.name)
def test_no_published_page_offers_a_markdown_link(page):
    dead = re.findall(r'href="[^"]*\.md(?:#[^"]*)?"', page.read_text(encoding="utf-8"))
    assert not dead, f"{page.name} links to unpublishable Markdown: {dead[:5]}"


def test_the_published_manual_actually_cross_references_itself():
    """A relink() that stripped every link would pass the negative test."""
    readme = (ROOT / "site" / "docs" / "readme.html").read_text(encoding="utf-8")
    assert 'href="management-overview.html"' in readme
    assert 'href="cli.html"' in readme
    # ...and the target of a rewritten link must actually be published.
    for slug in re.findall(r'href="([a-z0-9-]+)\.html"', readme):
        if slug in ("docs", "index"):
            continue
        assert (ROOT / "site" / "docs" / f"{slug}.html").exists(), slug


def test_relink_maps_a_published_document_and_keeps_the_anchor():
    out = pubdoc.relink('<a href="./api_v1.md#3-endpoints">API</a>')
    assert out == '<a href="api.html#3-endpoints">API</a>'


def test_relink_unwraps_a_link_to_an_unpublished_document():
    """A link that cannot resolve becomes its own text, not a lie."""
    out = pubdoc.relink('<a href="../nowhere.md">gone</a>')
    assert out == "gone"
    assert ".md" not in out


def test_every_markdown_file_that_can_be_linked_is_published():
    """Guarantees the unwrap branch is a backstop, not the normal path."""
    unpublished = [f.name for f in (ROOT / "docs").glob("*.md")
                   if f.name not in pubdoc.SLUG_BY_FILE]
    assert not unpublished, f"docs/ carries unpublished manuals: {unpublished}"


def test_the_device_api_manual_is_published_and_grouped():
    assert "device-api.md" in pubdoc.SLUG_BY_FILE
    assert pubdoc.SLUG_BY_FILE["device-api.md"] == "device-api"
    grouped = {slug for _n, _l, slugs in pubdoc.GROUPS for slug in slugs}
    assert "device-api" in grouped
    page = (ROOT / "site" / "docs" / "device-api.html").read_text(encoding="utf-8")
    # The whole point of the document: the two APIs are told apart.
    assert "endpoint registry" in page.lower()
    for console in ("/web/api-explorer/", "/adc/api/", "/faz/api/"):
        assert console in page, f"the manual omits the {console} console"
