"""One SATOM mark — the emblem the product already shipped — on every surface.

Second pass, 2026-08-10. The first pass read "cambia el nombre del logo" as
"replace the artwork" and swapped the emblem for an invented rounded-square
"S." mark on five nodes at once. The instruction was narrower, and the
difference is the whole point: **the artwork was never the defect. The VENDOR
NAME attached to it was.** Replacing a product's identity is the change where
nothing fails — every page still renders, every asset still answers 200, the
tab still shows *an* icon — so the only thing that can catch it is a guard
that pins WHICH mark is canonical.

So these guards run in both directions:

* the emblem is canonical and byte-identical on every surface (it used to be
  three files that nothing forced to agree, which is how a rebrand ends up
  half-applied);
* the invented vector must not come back — neither as a file nor as a
  reference from any chrome;
* nothing **we** name may carry the vendor's name. Nominative use stays in
  place on purpose: a row that says which kind of appliance it describes, or a
  capacity ceiling attributed to the vendor's datasheet, is a fact about
  someone else's product. A background preset called "Fortinet" inside OUR
  settings menu is us wearing their name.

The vendor-glyph guards (the deleted ``favicon.svg``, its HTTP 404 and the
sweep for the corporate red) live in ``tests/test_favicon.py`` — §8d — and are
deliberately not duplicated here.
"""
from __future__ import annotations

import hashlib
import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]

MARK = ROOT / "app" / "static" / "img" / "satom-mark.png"
SITE_MARK = ROOT / "site" / "assets" / "satom-mark.png"

# The mark this round REVERTED. Named so a future reader knows the string is a
# tombstone, not a target.
INVENTED_VECTOR = "satom-mark.svg"


def _digest(p: pathlib.Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def _live_templates():
    """Editor backups under ``backups/`` are dead text, not surfaces."""
    return [p for p in (ROOT / "app" / "templates").rglob("*.html")
            if ".bak" not in p.name and ".pre-" not in p.name]


def _site_pages():
    return sorted((ROOT / "site").rglob("*.html"))


BRAND_ANCHOR = re.compile(r'<a class="brand".*?</a>', re.S)
BRAND_IMG = re.compile(r'<img[^>]*class="mark"[^>]*>')
ICON_LINKS = re.compile(r'<link rel="[^"]*icon[^"]*"[^>]*>')


def _brand_chrome(page: pathlib.Path) -> str:
    """The header brand plus the icon links — the CHROME, never the body.

    Scanning a whole page is the eighth assert-by-substring in this repo to
    match its own documentation: the generated CHANGELOG and safeguards pages
    NAME these files in prose while linking the right one, and a full-page
    sweep calls that a regression.
    """
    text = page.read_text()
    return "\n".join(BRAND_ANCHOR.findall(text)
                     + BRAND_IMG.findall(text)
                     + ICON_LINKS.findall(text))


# ── the emblem is shipped, under the product's name ────────────────────────
@pytest.mark.parametrize("rel", [
    "app/static/img/satom-mark.png",
    "site/assets/satom-mark.png",
])
def test_the_emblem_is_shipped_under_the_product_name(rel):
    assert (ROOT / rel).is_file(), (
        "%s is missing — the brand mark must be findable by the product's "
        "name, not by one of its uses (favicon/icon)" % rel)


def test_every_copy_of_the_mark_is_byte_identical():
    copies = {"app/static/img/satom-mark.png": _digest(MARK),
              "site/assets/satom-mark.png": _digest(SITE_MARK)}
    assert len(set(copies.values())) == 1, (
        "the shipped marks have drifted apart: %s" % copies)


def test_the_emblem_keeps_its_geometry_and_alpha():
    """A mark that loses its alpha grows an opaque square that fights every
    header it is dropped into; a mark that changes aspect stops being the same
    logo at 28px."""
    Image = pytest.importorskip("PIL.Image")
    for p in (MARK, SITE_MARK):
        im = Image.open(p)
        assert im.size == (256, 256), "%s is %s" % (p.name, im.size)
        assert im.mode == "RGBA", "%s lost its alpha (%s)" % (p.name, im.mode)


# ── the invented vector must not come back ─────────────────────────────────
@pytest.mark.parametrize("rel", [
    "app/static/img/satom-mark.svg",
    "site/assets/satom-mark.svg",
])
def test_the_invented_vector_is_not_shipped(rel):
    assert not (ROOT / rel).is_file(), (
        "%s is back. That file is the substitute mark this round reverted; the "
        "product's identity is the emblem raster." % rel)


def test_no_live_template_requests_the_invented_vector():
    offenders = [str(p.relative_to(ROOT)) for p in _live_templates()
                 if INVENTED_VECTOR in p.read_text()]
    assert offenders == [], (
        "these templates still request the reverted mark: %s" % offenders)


def test_no_site_chrome_requests_the_invented_vector():
    offenders = [str(p.relative_to(ROOT)) for p in _site_pages()
                 if INVENTED_VECTOR in _brand_chrome(p)]
    assert offenders == [], (
        "these site pages still request the reverted mark: %s" % offenders)


# ── every brand surface actually shows it ──────────────────────────────────
BRAND_SURFACES = ("base.html", "auth/login.html", "product/select.html",
                  "auth/profile.html")


@pytest.mark.parametrize("rel", BRAND_SURFACES)
def test_every_console_brand_surface_falls_back_to_the_emblem(rel):
    """One theme logo, one fallback, three surfaces. When base.html fell back
    to ``product.mark`` the header drew the ADOM globe instead of the product,
    and only on themes with no uploaded logo — a defect visible in one
    configuration out of two."""
    text = (ROOT / "app" / "templates" / rel).read_text()
    assert "img/satom-mark.png" in text, (
        "%s does not fall back to the product mark" % rel)


def test_every_site_page_shows_the_mark_in_its_header():
    """A header that renders only the wordmark is the placeholder state this
    work removed; it must not come back one page at a time."""
    missing = [str(p.relative_to(ROOT)) for p in _site_pages()
               if 'class="brand"' in p.read_text()
               and "satom-mark.png" not in _brand_chrome(p)]
    assert missing == [], "these pages render a brand with no mark: %s" % missing


def test_the_generator_template_agrees_with_the_pages_it_regenerates():
    """Two authors of one string is how ``index.html`` lost its Docs link: a
    page fixed by hand is reverted by the next regeneration."""
    gen = (ROOT / "deploy" / "gen_site_docs.py").read_text()
    assert "assets/satom-mark.png" in gen, (
        "the site generator no longer stamps the emblem — every regenerated "
        "page would revert")
    assert INVENTED_VECTOR not in gen, (
        "the generator still stamps the reverted mark")


# ── nothing WE name carries the vendor's name ──────────────────────────────
VENDOR = re.compile(r"forti", re.I)


SETTINGS_STORE = ROOT / "app" / "services" / "settings_store.py"


def _banner_templates_block() -> str:
    """The literal dict of shipped banner choices.

    NOT ``LOGIN_BG_PRESETS`` — that name only ever existed in safeguards.md.
    The live constant is ``BANNER_TEMPLATES``, read by ``auth/routes.py`` to
    build the login banner picker, so it is a USER-VISIBLE list of names, not
    dead configuration. Believing the doc's name instead of grepping the code
    is what made the first version of this guard fail against a correct file.
    """
    src = SETTINGS_STORE.read_text()
    m = re.search(r"^BANNER_TEMPLATES\s*=\s*\{.*?^\}", src, re.S | re.M)
    assert m, "BANNER_TEMPLATES not found — did the constant move or rename?"
    return m.group(0)


def test_no_banner_template_we_ship_is_named_after_the_vendor():
    """``BANNER_TEMPLATES`` shipped an entry keyed ``fortinet`` labelled
    "Fortinet" — a choice offered in OUR login settings under THEIR name, next
    to an "Ember Red" that already covered the same taste. Nothing failed,
    because a name is an assertion and an assertion has no exit code."""
    block = _banner_templates_block()
    offenders = [l.strip() for l in block.splitlines() if VENDOR.search(l)]
    assert offenders == [], (
        "a banner template is named after the vendor:\n%s"
        % "\n".join(offenders))


def test_the_renamed_banner_id_still_resolves_so_nothing_is_repainted():
    """Deleting the key outright would have been the *silent* version of this
    change: ``banner_template`` falls through to "slate", so any ADOM that had
    chosen it gets repainted with no trace. The alias keeps the stored id
    rendering the colour it always rendered."""
    src = SETTINGS_STORE.read_text()
    assert 'BANNER_TEMPLATE_ALIASES = {"fortinet": "crimson"}' in src, (
        "the legacy banner id no longer maps anywhere; stored selections would "
        "silently fall back to the default")
    assert "crimson" in _banner_templates_block(), (
        "the alias points at a template that is not shipped — a stored id would "
        "resolve to nothing")
    # both readers must go through the alias, not just the global one
    for rel in ("app/services/settings_store.py",
                "app/services/user_settings_store.py"):
        assert "resolve_banner_template(" in (ROOT / rel).read_text(), (
            "%s reads a stored banner id without resolving renames" % rel)


ICON_WORDS = re.compile(r"favicon|icon|logo|mark|brand", re.I)


def test_the_brand_chrome_of_the_console_does_not_name_the_vendor():
    """The favicon block carried ``<!-- Favicon (Fortinet) -->``. A comment is
    not served, but it is what the next reader believes the asset IS — and that
    belief is how the vendor glyph kept its seat through three renames (§8d).

    Scoped to comments that are ABOUT an icon/logo: ``<!-- FortiWeb CSS -->``
    labels ``css/fortiweb.css`` correctly and is nominative use. A bare sweep
    for the vendor across the <head> flagged it — the ninth assert-by-substring
    in this repo to match something it never meant.
    """
    base = (ROOT / "app" / "templates" / "base.html").read_text()
    head = base.split("<body", 1)[0]
    offenders = [l.strip() for l in head.splitlines()
                 if l.lstrip().startswith("<!--")
                 and ICON_WORDS.search(l) and VENDOR.search(l)]
    assert offenders == [], (
        "the console <head> names the vendor in its own brand chrome: %s"
        % offenders)


# ── the enumerated list above rots; this is what notices ────────────────────
#: Renders the console's own name/logo but is NOT a brand surface: the branding
#: settings page prints ``settings.app_name`` into a form FIELD and uploads the
#: theme asset -- it has no emblem of its own to get wrong.
NON_EMBLEM_IDENTITY_PAGES = {"settings/index.html"}


def _identity_templates():
    """Templates that render the CONSOLE's own identity -- its configured name
    or its theme logo. This is the roster BRAND_SURFACES is supposed to be."""
    out = []
    for p in _live_templates():
        text = p.read_text()
        if "settings.app_name" in text or "theme_logo_url" in text:
            out.append(str(p.relative_to(ROOT / "app" / "templates")))
    return sorted(out)


def test_no_identity_surface_is_missing_from_the_enumeration():
    """BRAND_SURFACES is an enumerated allowlist over a tree that grows, so it
    stops covering WITHOUT EVER FAILING -- that is exactly how the profile
    About card drew the ADOM globe for four releases while every brand test
    stayed green. Derive the roster and make the omission itself the failure:
    a new page that shows the console's name or logo must be classified, not
    silently uncovered."""
    unclassified = [rel for rel in _identity_templates()
                    if rel not in BRAND_SURFACES
                    and rel not in NON_EMBLEM_IDENTITY_PAGES]
    assert unclassified == [], (
        "these templates render the console's own identity but are in neither "
        "BRAND_SURFACES nor NON_EMBLEM_IDENTITY_PAGES: %s" % unclassified)


def test_the_about_card_does_not_draw_the_active_adom():
    """``product.mark`` is the ACTIVE ADOM's icon. Under Global it is a globe;
    inside a FortiWeb ADOM it is the FortiWeb logo. Either one next to the
    console's own name and version is a false claim about what this is, which
    is the same class of defect as the ``v1.0`` literal this card shipped."""
    import re as _re
    text = (ROOT / "app" / "templates" / "auth" / "profile.html").read_text()
    # Strip Jinja comments FIRST: the comment that explains this guard names
    # ``product.mark``, and a substring assert that matches its own rationale
    # passes against the defect it is written for.
    text = _re.sub(r"\{#.*?#\}", "", text, flags=_re.S)
    assert "product.mark" not in text, (
        "auth/profile.html renders the ADOM mark; the About card must use the "
        "brand emblem (theme_logo_url or img/satom-mark.png)")


def test_the_version_badge_sits_beside_the_product_name():
    """The badge used to hang under the tagline, two lines below the name it
    qualifies -- so the card read as a product blurb with a loose number under
    it. Name and version are ONE claim; they render on one line."""
    text = (ROOT / "app" / "templates" / "auth" / "profile.html").read_text()
    end_name = text.index("</h5>")
    badge = text.index("v{{ app_version }}")
    tagline = text.index("System Automation")
    assert end_name < badge < tagline, (
        "the version badge is no longer adjacent to the product name "
        "(name ends %d, badge %d, tagline %d)" % (end_name, badge, tagline))
