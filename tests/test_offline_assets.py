"""Nothing the console loads in a browser comes from another origin.

SATOM ships offline installers for isolated management networks. A browser
there cannot reach a CDN, and a stylesheet it cannot reach is not an error the
operator sees: every reload waits for the request to time out (10-20 s) and
the page comes back without icons. That was the state of 2.4.1, where Bootstrap
Icons alone still came from cdn.jsdelivr.net -- in five templates and in the
CSP -- right under a comment saying "Vendored, not a CDN". The older guards
only knew the names of the assets vendored before it (``bootstrap@``, Chart.js),
so the next one walked past them.

These tests do not list asset names. They forbid the shape: any template,
first-party stylesheet or script that loads from another origin, and any CSP
directive that would let it. Third-party code lives in ``app/static/vendor/``,
declared in ``MANIFEST.json`` with its version, licence, source and hashes.
See docs/engineering.md §9.1 and safeguards §199.
"""
import hashlib
import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "app" / "static"
VENDOR = STATIC / "vendor"
MANIFEST = VENDOR / "MANIFEST.json"

# An asset-loading construct whose target is another origin: absolute
# http(s):// or protocol-relative //. Plain <a href="https://..."> links are
# navigation, not loads, and stay allowed.
_ORIGIN = r"""(?:https?:)?//"""
_TAG = re.compile(
    r"""<(?:link|script|img|iframe|source|audio|video|embed|object)\b[^>]*?"""
    r"""\b(?:href|src|data)\s*=\s*\\?["']\s*""" + _ORIGIN, re.I)
_CSS = re.compile(
    r"""(?:url\(\s*["']?\s*|@import\s+["']\s*)""" + _ORIGIN, re.I)
_JS = re.compile(
    r"""(?:\bimport\s*\(\s*|\bfrom\s+|\bimportScripts\s*\(\s*|\.src\s*=\s*)"""
    r"""["'`]\s*""" + _ORIGIN, re.I)


def _first_party(pattern):
    return sorted(p for p in STATIC.rglob(pattern) if VENDOR not in p.parents)


def _hits(regex, text):
    return [text[max(m.start() - 40, 0):m.end() + 60].replace("\n", " ")
            for m in regex.finditer(text)]


def _manifest():
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


# --------------------------------------------------------------------------- #
# 1. No template, stylesheet or script loads from another origin              #
# --------------------------------------------------------------------------- #
def test_no_template_loads_an_asset_from_another_origin():
    bad = {}
    for p in sorted((ROOT / "app" / "templates").rglob("*.html")):
        text = p.read_text(encoding="utf-8")
        found = _hits(_TAG, text) + _hits(_CSS, text)
        if found:
            bad[str(p.relative_to(ROOT))] = found
    assert not bad, "vendor these under app/static/vendor/: %r" % bad


def test_no_first_party_stylesheet_loads_from_another_origin():
    bad = {str(p.relative_to(ROOT)): _hits(_CSS, p.read_text(encoding="utf-8"))
           for p in _first_party("*.css")}
    assert not {k: v for k, v in bad.items() if v}


def test_no_first_party_script_loads_from_another_origin():
    bad = {}
    for p in _first_party("*.js"):
        text = p.read_text(encoding="utf-8")
        found = _hits(_JS, text) + _hits(_TAG, text)
        if found:
            bad[str(p.relative_to(ROOT))] = found
    assert not bad


def test_the_scanners_recognise_what_they_forbid():
    """Without this the three scans above could go vacuous and stay green."""
    cdn = "https://cdn.jsdelivr.net/npm/x@1/x.css"
    assert _TAG.search('<link rel="stylesheet" href="%s">' % cdn)
    assert _TAG.search('<script src="//unpkg.com/x"></script>')
    assert _CSS.search("@import url(%s);" % cdn)
    assert _CSS.search('@font-face{src:url("https://fonts.gstatic.com/a.woff2")}')
    assert _JS.search('import("https://esm.sh/x")')
    assert _JS.search("s.src = 'https://cdn.example.net/x.js'")
    assert not _TAG.search('<a href="https://www.chartjs.org/">docs</a>')
    assert not _TAG.search(
        """<link rel="stylesheet" href="{{ url_for('static', filename='vendor/x.css') }}">""")


# --------------------------------------------------------------------------- #
# 2. The CSP would refuse a third-party script, style or font anyway          #
# --------------------------------------------------------------------------- #
_LOCAL_TOKENS = {"'self'", "'none'", "'unsafe-inline'", "data:"}


def test_the_csp_names_no_third_party_origin_for_code_styles_or_fonts(client):
    csp = client.get("/auth/login").headers["Content-Security-Policy"]
    directives = dict(
        (part.split()[0], part.split()[1:])
        for part in (d.strip() for d in csp.split(";")) if part)
    for name in ("default-src", "script-src", "script-src-elem", "style-src",
                 "style-src-elem", "font-src"):
        assert name in directives, name
        foreign = [t for t in directives[name]
                   if t not in _LOCAL_TOKENS and not t.startswith("'nonce-")]
        assert not foreign, "%s allows %r" % (name, foreign)


# --------------------------------------------------------------------------- #
# 3. Every vendored file is declared, hashed and actually served              #
# --------------------------------------------------------------------------- #
def test_every_vendored_file_is_in_the_manifest_with_its_hash():
    declared = {}
    for asset in _manifest()["assets"]:
        for key in ("name", "version", "license", "homepage", "source", "files"):
            assert asset.get(key), (asset.get("name"), key)
        declared.update(asset["files"])
    on_disk = {str(p.relative_to(VENDOR)) for p in VENDOR.rglob("*")
               if p.is_file() and p != MANIFEST}
    assert on_disk == set(declared), (
        "undeclared: %r / missing: %r"
        % (sorted(on_disk - set(declared)), sorted(set(declared) - on_disk)))
    for rel, digest in declared.items():
        assert hashlib.sha256((VENDOR / rel).read_bytes()).hexdigest() == digest, rel


def test_vendored_stylesheets_only_point_at_files_that_ship():
    """Bootstrap Icons' CSS reaches its fonts by relative url(); a vendored
    stylesheet whose font is missing renders exactly like the CDN outage."""
    for css in VENDOR.rglob("*.css"):
        text = css.read_text(encoding="utf-8")
        assert not _hits(_CSS, text), css
        for ref in re.findall(r"""url\(\s*["']?([^"')]+)""", text):
            if ref.startswith("data:"):
                continue
            target = (css.parent / ref.split("?")[0].split("#")[0]).resolve()
            assert target.is_file(), "%s -> %s" % (css.relative_to(ROOT), ref)


def test_every_vendored_asset_is_credited_and_documented():
    notice = (ROOT / "NOTICE").read_text(encoding="utf-8")
    manual = (ROOT / "docs" / "engineering.md").read_text(encoding="utf-8")
    for asset in _manifest()["assets"]:
        assert asset["name"] in notice and asset["homepage"] in notice, asset["name"]
        row = "| %s | %s |" % (asset["name"], asset["version"])
        assert row in manual, "docs/engineering.md §9.1 lacks %r" % row
        assert asset["source"] in manual, asset["source"]


@pytest.mark.parametrize("rel,mime", [
    ("bootstrap-icons/bootstrap-icons.min.css", "text/css"),
    ("bootstrap-icons/fonts/bootstrap-icons.woff2", "font/woff2"),
    ("bootstrap-icons/fonts/bootstrap-icons.woff", "font/woff"),
])
def test_the_icon_font_is_served_by_the_app(client, rel, mime):
    resp = client.get("/static/vendor/" + rel)
    assert resp.status_code == 200
    assert resp.mimetype == mime


# --------------------------------------------------------------------------- #
# 4. The page fade can never outlive itself (the unclickable modal)           #
# --------------------------------------------------------------------------- #
def _fade_handler():
    src = (STATIC / "js" / "turbo-boot.js").read_text(encoding="utf-8")
    start = src.index("var cls = whole ? 'fw-entering-page' : 'fw-entering';")
    return src[start:src.index("});", src.index("setTimeout(done", start))]


def test_reduced_motion_never_gets_the_fade_class():
    """fortiweb.css sets `animation: none` under prefers-reduced-motion, so
    animationend never fires. The class then stays, its will-change:transform
    makes #fw-main a stacking context, and Bootstrap's body-level backdrop
    covers every modal inside it: visible form, no clicks. Reproduced in
    Chromium on 2026-10-01 (safeguards §199)."""
    body = _fade_handler()
    check = body.find("(prefers-reduced-motion: reduce)")
    assert check != -1
    assert check < body.index("target.classList.add(cls)")


def test_the_fade_class_never_depends_on_a_single_event():
    body = _fade_handler()
    assert "addEventListener('animationend', done)" in body
    assert "addEventListener('animationcancel', done)" in body
    timer = re.search(r"setTimeout\(done,\s*(\d+)\)", body)
    assert timer and 450 < int(timer.group(1)) <= 2000
