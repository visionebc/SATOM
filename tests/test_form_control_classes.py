"""A form control whose only class does not exist is painted with the
browser defaults: no SATOM border, no focus ring, and a <select> without
'form-select' comes out with the operating system's native dropdown.

The page still returns 200, no route test notices and nobody sees it until
a human looks. That is exactly how 'fw-input' -- a class that is NOT defined
in any CSS -- survived 10 uses in console/index.html from 2026-06-27 to
2026-09-21.

This guard reads the <input>/<select>/<textarea> of ALL the templates and
requires at least one of their classes to be defined somewhere real:
app/static/css/*.css, vendored bootstrap, or the <style> of their own page.
"""
import re
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
TPL = ROOT / "app" / "templates"
CSS_DIR = ROOT / "app" / "static" / "css"
BOOTSTRAP = ROOT / "app" / "static" / "vendor" / "bootstrap" / "bootstrap.min.css"

CTRL = re.compile(r"<(input|select|textarea)\b[^>]*>", re.S)
SELECTOR = re.compile(r"\.([A-Za-z][A-Za-z0-9_-]+)")
STYLE_BLOCK = re.compile(r"<style[^>]*>(.*?)</style>", re.S)
CLASS_ATTR = re.compile(r'class="([^"]*)"')
# spacing/sizing utilities: they add no visual identity, they do not count
UTILITY = re.compile(
    r"(m|p)[tbxysel]?-\d|w-\d+|h-\d+|d-\w+|flex-\S+|text-\S+|font-\S+"
    r"|align-\S+|float-\S+|g-\d"
)

# Frozen debt, measured 2026-09-21. The guard is a ratchet: adding an unstyled
# control FAILS, and fixing one of these also fails (it has to be removed from
# the list on purpose). No entries are added without reading the control.
KNOWN_UNSTYLED = {
    ("exceptions/list.html", "det-pick"),
    ("faz/section.html", "fazdev-sel"),
    ("plugins/editor.html", "ds-cb"),
    ("plugins/editor.html", "pb-required"),
    ("workspace/_fields.html", "input_cls fw-toggle"),
    ("workspace/policies.html", "fw-pol-check"),
    ("workspace/policy_detail.html", "fw-cr-default fw-toggle"),
}


def _global_selectors():
    text = "".join(p.read_text(errors="ignore") for p in sorted(CSS_DIR.glob("*.css")))
    text += BOOTSTRAP.read_text(errors="ignore")
    return set(SELECTOR.findall(text))


def _offenders():
    known_global = _global_selectors()
    out = set()
    for path in sorted(TPL.rglob("*.html")):
        raw = path.read_text(errors="ignore")
        local = set(SELECTOR.findall("".join(STYLE_BLOCK.findall(raw))))
        known = known_global | local
        for match in CTRL.finditer(raw):
            tag = match.group(0)
            if 'type="hidden"' in tag:
                continue
            attr = CLASS_ATTR.search(tag)
            if not attr:
                continue
            # a token with Jinja inside cannot be resolved statically
            classes = [c for c in attr.group(1).split() if "{" not in c and "}" not in c]
            meaningful = [c for c in classes if not UTILITY.fullmatch(c)]
            if meaningful and not any(c in known for c in meaningful):
                rel = path.relative_to(TPL).as_posix()
                out.add((rel, " ".join(meaningful)))
    return out


def test_bootstrap_and_css_are_readable():
    # if the CSS cannot be read, everything would come out 'unstyled' and the
    # guard would bite for the wrong reason -- or worse, the frozen list would hide it
    assert BOOTSTRAP.exists(), BOOTSTRAP
    assert len(_global_selectors()) > 500


def test_no_new_unstyled_form_controls():
    found = _offenders()
    new = found - KNOWN_UNSTYLED
    assert not new, (
        "form controls whose only class does not exist in any CSS "
        "(they are painted with the browser defaults): " + repr(sorted(new))
    )


def test_frozen_list_has_not_silently_grown():
    found = _offenders()
    fixed = KNOWN_UNSTYLED - found
    assert not fixed, (
        "these are already fixed: remove them from KNOWN_UNSTYLED so the "
        "ratchet does not allow reintroducing them: " + repr(sorted(fixed))
    )


def test_console_page_uses_house_form_classes():
    raw = (TPL / "console" / "index.html").read_text()
    assert "fw-input" not in raw, "fw-input does not exist in any CSS"
    assert raw.count("form-select fw-form-control") == 2, "the 2 <select>s"
    assert raw.count("form-control fw-form-control") == 8, "inputs + textareas"
    for match in CTRL.finditer(raw):
        tag = match.group(0)
        if 'type="hidden"' in tag or "form-check-input" in tag:
            continue
        attr = CLASS_ATTR.search(tag)
        assert attr, tag[:80]
        assert "fw-form-control" in attr.group(1), tag[:80]
