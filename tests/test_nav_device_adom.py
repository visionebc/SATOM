"""Guards for the sidebar's Device entry when the row is one ADOM of a chassis.

A FortiWeb in ADOM mode can only be registered one row per ADOM (the auth
token carries exactly one -- see test_chassis_grouping), and operators name
those rows ``<device>@<adom>`` by hand. That name plus the "change" hint is
wider than the 260px rail, and ``.fw-nav-item`` is ``white-space: nowrap``, so
the label OVERFLOWED the sidebar instead of wrapping.

The fix stacks it: the device keeps the clickable line, the ADOM reads as its
child underneath. These tests pin the two halves that can silently regress --
the split itself (which must never guess an ADOM the row is not in) and the
markup/CSS that keep the line inside the rail.
"""
import re

from pathlib import Path

from flask import render_template

from app import models

APP = Path(__file__).resolve().parents[1] / "app"
PARTIAL = APP / "templates" / "partials" / "nav_device_context.html"
CSS = APP / "static" / "css" / "fortiweb.css"


class _Row:
    """Duck-typed appliance row (no DB)."""

    def __init__(self, name, vdom=None, kind="fortiweb", host="192.0.2.14",
                 port=443, id=1):
        self.name = name
        self.vdom = vdom
        self.kind = kind
        self.host = host
        self.port = port
        self.id = id


# --------------------------------------------------------------------------- #
#  appliance_name_parts                                                         #
# --------------------------------------------------------------------------- #
def test_the_adom_suffix_is_lifted_out_of_the_name():
    assert models.appliance_name_parts(
        _Row("fortiweb09@adom_dev", vdom="adom_dev")) == ("fortiweb09", "adom_dev")


def test_a_row_with_no_adom_is_unchanged():
    """Most of the fleet has no ADOM. Those entries must render exactly as
    they did before, with no empty second line under them."""
    assert models.appliance_name_parts(_Row("fortiweb10", vdom="")) == \
        ("fortiweb10", "")
    assert models.appliance_name_parts(_Row("fortiweb10", vdom=None)) == \
        ("fortiweb10", "")


def test_an_adom_with_no_suffix_in_the_name_still_shows_its_adom():
    """fortiweb09 is registered in ADOM 'root' but named plainly. The ADOM is
    a property of the credential, not of the name the operator typed."""
    assert models.appliance_name_parts(_Row("fortiweb09", vdom="root")) == \
        ("fortiweb09", "root")


def test_a_suffix_that_disagrees_with_the_vdom_is_not_stripped():
    """The '@' convention is typed by hand and nothing enforces it. Trusting
    the text after '@' would print a domain this row does not administer --
    strictly worse than printing a long name."""
    assert models.appliance_name_parts(
        _Row("fortiweb09@adom_dev", vdom="adom_prod")) == \
        ("fortiweb09@adom_dev", "adom_prod")


def test_a_name_that_is_only_the_suffix_keeps_its_name():
    """Stripping here would leave the menu with a blank device."""
    assert models.appliance_name_parts(_Row("@root", vdom="root")) == \
        ("@root", "root")


def test_surrounding_whitespace_never_reaches_the_menu():
    assert models.appliance_name_parts(
        _Row("  fortiweb09@adom_dev  ", vdom=" adom_dev ")) == \
        ("fortiweb09", "adom_dev")


# --------------------------------------------------------------------------- #
#  the rendered partial                                                         #
# --------------------------------------------------------------------------- #
def _render(app, row):
    with app.test_request_context("/"):
        return render_template("partials/nav_device_context.html",
                               product={"key": "fortiweb", "name": "FortiWeb"},
                               current_appliance=row)


def _clickable_label(html):
    m = re.search(r'class="fw-nav-device-name">(.*?)</span>', html, re.S)
    return m.group(1) if m else ""


def test_the_clickable_line_carries_the_device_only(app):
    html = _render(app, _Row("fortiweb09@adom_dev", vdom="adom_dev"))
    label = _clickable_label(html)
    assert "fortiweb09" in label
    assert "adom_dev" not in label, \
        "the ADOM belongs on its own line, not appended to the device"


def test_the_adom_is_rendered_underneath(app):
    html = _render(app, _Row("fortiweb09@adom_dev", vdom="adom_dev"))
    m = re.search(r'fw-nav-device-adom"[^>]*>(.*?)</div>', html, re.S)
    assert m, "the ADOM sub-line is missing"
    assert "adom_dev" in m.group(1)
    # ...and it comes AFTER the device link, not before it.
    assert html.index("fw-nav-device-adom") > html.index("fw-nav-device-name")


def test_a_device_without_an_adom_gets_no_second_line(app):
    html = _render(app, _Row("fortiweb10", vdom=""))
    assert "fw-nav-device-adom" not in html
    assert "fortiweb10" in _clickable_label(html)


def test_the_full_name_survives_in_the_tooltip(app):
    """Truncating the visible label is only safe if the whole identity is
    still reachable -- otherwise two ADOMs of one chassis look identical."""
    html = _render(app, _Row("fortiweb09@adom_dev", vdom="adom_dev"))
    m = re.search(r'<a class="fw-nav-item"[^>]*title="([^"]*)"', html)
    assert m and "fortiweb09@adom_dev" in m.group(1)


def test_no_device_selected_still_prompts(app):
    html = _render(app, None)
    assert "Select a device" in html
    assert "fw-nav-device-adom" not in html


# --------------------------------------------------------------------------- #
#  the CSS that actually keeps it inside the rail                               #
# --------------------------------------------------------------------------- #
def _css_block(name):
    """The declarations of one selector, comments stripped.

    Comments are removed BEFORE matching because the comment that explains a
    guard tends to contain the very words the guard asserts on -- that is how
    a rule can be deleted while its test keeps passing.
    """
    src = re.sub(r"/\*.*?\*/", "", CSS.read_text(encoding="utf-8"), flags=re.S)
    m = re.search(re.escape(name) + r"\s*\{([^}]*)\}", src)
    return m.group(1) if m else ""


def test_the_device_label_truncates_instead_of_overflowing():
    block = _css_block(".fw-nav-context .fw-nav-device-name")
    assert "overflow: hidden" in block
    assert "text-overflow: ellipsis" in block
    assert "min-width: 0" in block, \
        "a flex child will not shrink below its content without this"


def test_the_adom_line_is_indented_under_the_device_text():
    block = _css_block(".fw-nav-device-adom")
    m = re.search(r"padding:\s*[^;]*?(\d+)px;", block)
    assert m, "the ADOM line needs a left indent to read as a child"
    assert int(m.group(1)) >= 40, \
        "16px rail padding + 18px icon + 10px gap = 44px is where the device text starts"


def test_the_adom_line_also_truncates():
    block = _css_block(".fw-nav-device-adom > span")
    assert "text-overflow: ellipsis" in block and "nowrap" in block
