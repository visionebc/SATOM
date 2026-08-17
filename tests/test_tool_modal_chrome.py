"""The three tool modals must be built out of classes that actually exist.

Reported 2026-08-17 by the user, twice: "Certificate inspector / False-positive
explainer / Transaction tracer tienen todavia el formato viejo".

The cause was not a taste disagreement. ``fortiweb.css`` defines
``.btn-fw-primary`` / ``.btn-fw-outline`` / ``.btn-fw-secondary`` /
``.btn-fw-danger``.  The three tools were written with the word order
REVERSED -- ``fw-btn-primary`` -- which matches no selector in any stylesheet
the product loads.  Ten buttons therefore rendered as the browser's native
grey, bevelled ``<button>`` inside a flat white modal.

Nothing failed.  The page rendered, the handlers fired, the modal opened, and
the round that shipped it verified "0 dark-theme tokens" -- which was true and
did not check that the classes it used resolved to a rule.  This is the same
shape as the ``.btn-fw-secondary`` note already in ``fortiweb.css``: *"was used
by 5 templates but never defined, so it fell back to an unstyled .btn"*.  The
product has now made this mistake twice, so it gets a guard.

Nothing here is a typed list of blessed class names.  The set of defined
classes is read from the stylesheets the product actually links, and the set of
element ids (which are NOT classes and must not be checked against CSS) is read
from the JavaScript itself.  A new tool, a new card or a renamed CSS class
moves both sets in the same commit.
"""
from __future__ import annotations

import io
import os
import re

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
JS_DIR = os.path.join(REPO, "app", "static", "js")
CSS_DIR = os.path.join(REPO, "app", "static", "css")
VENDOR_CSS = os.path.join(REPO, "app", "static", "vendor", "bootstrap", "bootstrap.min.css")

# The three tools this guard was written for, and the two that predate them and
# define the house chrome.  Both groups are read from disk; neither is a
# description of what the files ought to contain.
TOOLS = ("cert_inspect.js", "fp_triage.js", "txn_trace.js")
REFERENCE = ("net_calc.js", "regex_lab.js")


def _read(path):
    return io.open(path, encoding="utf-8").read()


@pytest.fixture(scope="module")
def stylesheets():
    """Every class selector the product's own + vendored stylesheets define."""
    text = ""
    for name in sorted(os.listdir(CSS_DIR)):
        if name.endswith(".css"):
            text += _read(os.path.join(CSS_DIR, name))
    text += _read(VENDOR_CSS)
    return set(re.findall(r"\.([A-Za-z0-9_-]+)", text))


@pytest.fixture(scope="module")
def tools():
    return {name: _read(os.path.join(JS_DIR, name)) for name in TOOLS}


def _ids(src):
    """Tokens the file uses as element IDS -- these are not classes.

    Derived from the two places an id can appear: the markup it emits and the
    lookups it performs.  Hard-coding the ``fw-ci-`` / ``fw-fp-`` / ``fw-tt-``
    prefixes instead would mean a fourth tool with a fourth prefix has every
    one of its ids reported as an undefined CSS class, and the guard gets an
    exception carved into it on its first real use.
    """
    found = set(re.findall(r'id="([A-Za-z0-9_-]+)"', src))
    found |= set(re.findall(r"""\$\(['"]([A-Za-z0-9_-]+)['"]\)""", src))
    found |= set(re.findall(r"""getElementById\(['"]([A-Za-z0-9_-]+)['"]\)""", src))
    found |= set(re.findall(r"""MODAL_ID = ['"]([A-Za-z0-9_-]+)['"]""", src))
    return found


def _product_tokens(src):
    """``fw-*`` / ``btn-fw-*`` tokens the file uses as CLASSES."""
    ids = _ids(src)
    tokens = set()
    # (a) tokens written inside a class attribute
    for attr in re.findall(r'class="([^"]*)"', src):
        tokens |= {c for c in attr.split() if c.startswith(("fw-", "btn-fw-"))}
    # (b) bare string literals that ARE a class, concatenated in at render time
    #     (the severity -> badge maps). Anchoring on the whole literal is what
    #     keeps `data-fw-certinspect-open` -- an ATTRIBUTE NAME, not a class --
    #     out of the set: a naive \bfw-\w+\b sweep reported it as an undefined
    #     class and the guard failed against correct markup.
    tokens |= set(re.findall(r"""['"]((?:btn-fw|fw)-[a-z0-9-]+)['"]""", src))
    return {t for t in tokens if t not in ids}


# --------------------------------------------------------------------------
# 1. the defect itself: a class that resolves to nothing
# --------------------------------------------------------------------------
@pytest.mark.parametrize("name", TOOLS)
def test_every_product_class_resolves_to_a_stylesheet_rule(name, tools, stylesheets):
    unknown = sorted(t for t in _product_tokens(tools[name]) if t not in stylesheets)
    assert not unknown, (
        "%s uses class(es) no stylesheet defines: %s. A class that matches no "
        "rule renders as the browser default and cannot fail a test on its own."
        % (name, ", ".join(unknown))
    )


@pytest.mark.parametrize("name", TOOLS)
def test_the_reversed_button_spelling_is_absent(name, tools):
    # The specific trap: btn-fw-primary is real, fw-btn-primary is not, and the
    # two differ only in word order. Read separately from the resolution test
    # because this one names the mistake for whoever the failure lands on.
    assert "fw-btn" not in tools[name], (
        "%s spells the button class fw-btn-*; fortiweb.css defines btn-fw-*. "
        "The word order is reversed and the rule never matches." % name
    )


@pytest.mark.parametrize("name", TOOLS)
def test_product_buttons_also_carry_the_bootstrap_btn_class(name, tools):
    # .btn-fw-* sets colour and border only -- padding, radius, line-height and
    # the pointer cursor all come from Bootstrap's .btn. Without it the button
    # is correctly coloured and the wrong size.
    for cls in re.findall(r'class="([^"]*btn-fw-[^"]*)"', tools[name]):
        # Token equality, NOT a \bbtn\b regex: "-" is a non-word character, so
        # \bbtn\b matches INSIDE "btn-fw-outline" and the assertion answers
        # itself. Caught by mutation, not by review.
        assert "btn" in cls.split(), (
            "%s: class %r uses btn-fw-* without .btn, which supplies the "
            "padding and radius." % (name, cls)
        )


# --------------------------------------------------------------------------
# 2. card structure -- the sub-elements, not ad-hoc padding utilities
# --------------------------------------------------------------------------
@pytest.mark.parametrize("name", TOOLS)
def test_cards_use_the_card_sub_structure(name, tools):
    src = tools[name]
    opens = len(re.findall(r'class="fw-card[ "]', src))
    bodies = src.count("fw-card-body")
    assert opens, "%s emits no fw-card at all -- the test is pointed at the wrong file" % name
    assert bodies >= opens, (
        "%s opens %d fw-card(s) but only %d have an fw-card-body. A bare "
        ".fw-card has zero padding: its content touches the border."
        % (name, opens, bodies)
    )


@pytest.mark.parametrize("name", TOOLS)
def test_cards_do_not_reinvent_padding_with_utilities(name, tools):
    # `fw-card p-3` was how the three tools substituted for the real
    # sub-structure: it produces 16px instead of the product's 20px and loses
    # the header tint and its bottom border entirely.
    bad = re.findall(r'class="fw-card p[xytb]?-\d', tools[name])
    assert not bad, (
        "%s pads an fw-card with Bootstrap utilities (%s) instead of using "
        "fw-card-header / fw-card-body." % (name, ", ".join(sorted(set(bad))))
    )


@pytest.mark.parametrize("name", TOOLS)
def test_card_headers_carry_a_card_title(name, tools):
    src = tools[name]
    headers = src.count("fw-card-header")
    titles = src.count("fw-card-title")
    assert titles >= headers, (
        "%s emits %d fw-card-header(s) but %d fw-card-title(s); a header "
        "without the title class loses the product's 14px/600 heading."
        % (name, headers, titles)
    )


# --------------------------------------------------------------------------
# 3. chrome parity with the two tools that predate these
# --------------------------------------------------------------------------
@pytest.fixture(scope="module")
def reference_chrome():
    """Modal-header markup as the two OLDER tools in the same menu write it."""
    src = "".join(_read(os.path.join(JS_DIR, n)) for n in REFERENCE)
    header = re.search(r'modal-header([^"\']*)', src)
    assert header, "neither reference tool emits a modal-header any more"
    return src


@pytest.mark.parametrize("name", TOOLS)
def test_modal_header_matches_the_house_density(name, tools, reference_chrome):
    # Opening Network Calculator and then Certificate inspector from the same
    # dropdown showed two different header heights. `py-2` is what the other
    # two use; it is read from them, not typed here.
    assert "modal-header py-2" in reference_chrome, (
        "the reference tools no longer use `modal-header py-2` -- update this "
        "guard to whatever the house chrome became, do not delete it"
    )
    assert "modal-header py-2" in tools[name], (
        "%s uses a modal-header without the house `py-2` density." % name
    )


@pytest.mark.parametrize("name", TOOLS)
def test_modal_title_is_an_h6(name, tools):
    assert re.search(r'<h6 class="modal-title mb-0"', tools[name]), (
        "%s titles its modal with something other than the house "
        '`<h6 class="modal-title mb-0">`.' % name
    )
    assert '<h5 class="modal-title"' not in tools[name], (
        "%s still uses the h5 modal title." % name
    )


@pytest.mark.parametrize("name", TOOLS)
def test_tabs_are_buttons_not_anchors(name, tools):
    # An <a href="#"> acting as a tab is not reachable the way a <button> is,
    # and it puts a fragment in the address bar on every switch.
    anchors = re.findall(r'<a class="nav-link[^"]*" href="#"', tools[name])
    assert not anchors, (
        "%s builds tabs out of <a href='#'>; regex_lab.js uses "
        "<button class='nav-link' type='button'>." % name
    )


@pytest.mark.parametrize("name", TOOLS)
def test_form_controls_use_the_small_variant(name, tools):
    # The modals are dense diagnostic forms; the rest of the product's modals
    # use the -sm controls. A full-size control next to a btn-sm looks broken.
    src = tools[name]
    for attr, small in (("form-control", "form-control-sm"), ("form-select", "form-select-sm")):
        plain = re.findall(r'class="%s(?![-\w])[^"]*"' % attr, src)
        for cls in plain:
            assert small in cls, (
                "%s: %r is a full-size control in a dense modal." % (name, cls)
            )


# --------------------------------------------------------------------------
# 4. the debt this defect came from, frozen so it cannot grow
# --------------------------------------------------------------------------
# The reversed spelling is NOT confined to these three files: it is spread
# across templates written earlier. Those buttons are unstyled today. Cleaning
# them is a separate, user-authorised change; what this guard does is stop the
# count going UP, and print it so it is never mistaken for zero.
DEAD_BUTTON_BUDGET = 108


def test_the_reversed_spelling_does_not_spread(capsys):
    hits = []
    for root, _dirs, files in os.walk(os.path.join(REPO, "app")):
        for f in files:
            if not f.endswith((".html", ".js")):
                continue
            path = os.path.join(root, f)
            n = len(re.findall(r"\bfw-btn", _read(path)))
            if n:
                hits.append((n, os.path.relpath(path, REPO)))
    total = sum(n for n, _ in hits)
    with capsys.disabled():
        print("\n  pre-existing unstyled fw-btn-* occurrences: %d in %d file(s)"
              % (total, len(hits)))
    assert total <= DEAD_BUTTON_BUDGET, (
        "the reversed button spelling spread to %d occurrences (budget %d). "
        "New code must use btn-fw-*." % (total, DEAD_BUTTON_BUDGET)
    )
