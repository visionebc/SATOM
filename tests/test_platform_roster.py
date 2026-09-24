"""Guards for the two defects of 2026-08-10 (profile + default platform).

Neither of them broke anything. Both simply CLAIMED something false, which is
the kind of failure no test was catching:

* The profile "About" card advertised ``v1.0`` -- correct for exactly one
  release, and it had been wrong for eight. A guard existed
  (``test_no_version_literal_in_the_templates_that_display_one``) but it walked
  an ENUMERATED LIST of two templates, and ``auth/profile.html`` was never on
  it. An enumerated allowlist over a growing tree is a guard that silently
  stops covering; here it is inverted -- ALL of them are swept and excluding
  one requires a reason.
* The default platform selector offered three options out of a roster of four
  families, and its server-side whitelist SILENTLY folded any other one into
  FortiWeb. Choosing FortiAuthenticator was saved as FortiWeb without a single
  error message.
"""
from __future__ import annotations

import pathlib
import re

import pytest

from tests.conftest import admin_user_id, login

ROOT = pathlib.Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "app" / "templates"
VERSION_LITERAL = re.compile(r"\bv\d+\.\d+(?:\.\d+)?\b")

#: Templates where a ``vN.M`` literal is NOT the application version.
#: Excluding requires a reason: that is what stops this list from becoming the
#: same enumerated allowlist that let the profile's ``v1.0`` through.
VERSION_LITERAL_EXEMPT = {
    "api_explorer/index.html": "v2.0 is the appliance's API version, not ours",
    "exceptions/index.html": "v2.0 is the appliance's API version",
    "registry/index.html": "v2.0 is the appliance's API version",
    "scheduled_actions/form.html": "v2.0 is the appliance's API version",
    "registry/versions.html": "v2.0 is the appliance's API version; "
                              "the ENTIRE page is about that",
}

#: A Jinja comment is removed on the server and never reaches a browser.
JINJA_COMMENT = re.compile(r"\{#.*?#\}", re.S)


def _strip_jinja_comments(text: str) -> str:
    """The text an operator can actually end up seeing.

    Without this filter the guard trips over the prose that explains it:
    change_requests/detail.html documents in a comment the card "that
    claimed v1.0 for eight releases" -- the historical defect this very
    test hunts. Flagging it as an offence forces exempting the whole file,
    and then a REAL literal gets in there unwatched.

    Non-greedy: two comments on one line cannot swallow what sits between them.
    """
    return JINJA_COMMENT.sub("", text)


def _live_templates() -> list[pathlib.Path]:
    return [p for p in sorted(TEMPLATES.rglob("*.html"))
            if ".bak" not in p.name and ".pre-" not in p.name]


# --------------------------------------------------------------------------
# The version: no template writes it by hand
# --------------------------------------------------------------------------

def test_no_template_anywhere_hardcodes_the_application_version():
    """Sweeps the ENTIRE tree, not a hand-written list.

    The previous guard named base.html and settings/index.html. The literal
    lived in auth/profile.html.
    """
    offenders = {}
    for path in _live_templates():
        rel = path.relative_to(TEMPLATES).as_posix()
        if rel in VERSION_LITERAL_EXEMPT:
            continue
        found = VERSION_LITERAL.findall(
            _strip_jinja_comments(path.read_text(encoding="utf-8")))
        if found:
            offenders[rel] = found
    assert not offenders, (
        f"version literal in {offenders}; use {{{{ app_version }}}} "
        "(app/version.py), or document the exemption in VERSION_LITERAL_EXEMPT"
    )


def test_the_exemption_list_has_no_dead_entries():
    """An exemption that no longer applies is an open, unwatched door."""
    dead = [rel for rel in VERSION_LITERAL_EXEMPT
            if not (TEMPLATES / rel).is_file()
            or not VERSION_LITERAL.search(_strip_jinja_comments(
                (TEMPLATES / rel).read_text(encoding="utf-8")))]
    assert not dead, f"exemptions that are no longer needed: {dead}"


def test_a_version_literal_in_a_jinja_comment_is_not_an_offender():
    """It is never rendered, so it cannot mislead anyone."""
    assert not VERSION_LITERAL.findall(
        _strip_jinja_comments("{# the card that claimed v1.0 for releases #}"))


def test_a_version_literal_outside_a_comment_is_still_an_offender():
    """The filter cannot be a back door."""
    assert VERSION_LITERAL.findall(
        _strip_jinja_comments("<b>v1.0</b>{# this one IS a comment #}"))


def test_stripping_does_not_swallow_what_sits_between_two_comments():
    """A greedy ``.*`` would eat the literal in the middle and go green."""
    assert VERSION_LITERAL.findall(
        _strip_jinja_comments("{# a #}<b>v9.9</b>{# b #}")) == ["v9.9"]


def test_the_profile_about_card_interpolates_the_version(app, client):
    """The exact surface that was wrong, actually rendered."""
    from app.version import app_version

    login(client, admin_user_id(app), product="global")
    body = client.get("/auth/profile", follow_redirects=True).get_data(as_text=True)
    assert f"v{app_version()}" in body, "the About card does not show the live version"


# --------------------------------------------------------------------------
# The About card cannot advertise a single family
# --------------------------------------------------------------------------

@pytest.mark.parametrize("claim", [
    "API Target",
    "FortiWeb 7.6 REST API",
    "Custom FortiWeb 7.6 Theme",
    "FortiWeb &amp; FortiADC management console",
])
def test_the_about_card_makes_no_single_family_claim(claim):
    """SATOM routes FOUR clients (app/models.py). Advertising the API of a
    single family was not incomplete: it was false."""
    text = (TEMPLATES / "auth" / "profile.html").read_text(encoding="utf-8")
    assert claim not in text, f"the About card still claims {claim!r}"


# --------------------------------------------------------------------------
# The platform roster has ONE author
# --------------------------------------------------------------------------

def test_the_settings_template_does_not_carry_its_own_platform_list():
    """Two authors of one list is how it ended up without FortiAuthenticator.

    Only the ``<select name="default_kind">`` block is inspected: the rest of
    the page names platforms legitimately (labels, help text, other tables).
    """
    text = (TEMPLATES / "settings" / "index.html").read_text(encoding="utf-8")
    block = re.search(r'<select name="default_kind".*?</select>', text, re.S)
    assert block, "the default platform selector has disappeared"
    body = block.group(0)
    hardcoded = re.findall(r'<option value="(?!\{\{)([^"]+)"', body)
    assert not hardcoded, (
        f"hand-written options {hardcoded}; the roster comes from "
        "product_scope.device_products()"
    )


def test_every_family_the_product_routes_is_offered(app):
    """The selector's roster = the product's roster. Nothing subtracted."""
    from app.services import product_scope

    keys = {k for k, _ in product_scope.device_products()}
    assert {"fortiweb", "fortiadc", "fortiauthenticator", "fortianalyzer"} <= keys


def test_the_server_accepts_every_family_in_the_roster(app):
    """The template is a hint; THIS is the rule.

    With the hand-written whitelist, ``fortiauthenticator`` was saved as
    ``fortiweb`` without an error message: the operator chose one thing and
    the system saved another.
    """
    from app.services import product_scope, settings_store

    for key, _ in product_scope.device_products():
        assert settings_store.normalise_default_kind(key) == key, (
            f"the server-side guard does not accept {key!r}, which IS in the roster"
        )


@pytest.mark.parametrize("posted", ["", None, "fortiswitch", "../../etc/passwd", "FortiWeb-Cloud"])
def test_a_value_outside_the_roster_never_survives(app, posted):
    """A hand-posted ``default_kind`` cannot land as-is."""
    from app.services import product_scope, settings_store

    got = settings_store.normalise_default_kind(posted)
    assert got in {k for k, _ in product_scope.device_products()}


@pytest.mark.parametrize("legacy,expected", [
    ("FortiWeb", "fortiweb"),
    ("FortiADC", "fortiadc"),
    ("FortiWeb-Cloud", "fortiweb"),
])
def test_the_values_stored_before_the_roster_still_read_back(app, legacy, expected):
    """Without the migration, an old install opens the page with NO option
    selected and the operator reads that their setting was lost."""
    from app.services import settings_store

    assert settings_store.normalise_default_kind(legacy) == expected


def test_the_save_path_itself_rejects_a_value_outside_the_roster(app):
    """The WRITE PATH, not the helper.

    This test exists because a mutation demanded it: reverting
    ``save_general`` to its hand-written three-value whitelist, every other
    guard in this file stayed green -- they checked ``normalise_default_kind``
    in isolation and nobody checked that the code that WRITES actually uses
    it. It was exactly the reported bug, and the guard did not see it.
    """
    from app.services import settings_store as ss

    with app.app_context():
        for key, _ in ss.platform_choices():
            ss.save_general(app_name="SATOM", default_kind=key, session_timeout=60,
                            poll_interval=30, show_raw_config=False, log_levels=["INFO"])
            assert ss.general()["default_kind"] == key, (
                f"saving {key!r} does not keep it: the write path does not "
                "go through the roster"
            )

        # And a value from outside cannot land as-is.
        ss.save_general(app_name="SATOM", default_kind="fortiswitch", session_timeout=60,
                        poll_interval=30, show_raw_config=False, log_levels=["INFO"])
        got = ss.general()["default_kind"]
        assert got in {k for k, _ in ss.platform_choices()}, got


def test_the_default_platform_is_actually_preselected(app, client):
    """The help text promises "Pre-selected when registering a new
    appliance". Until today NOBODY read the setting: it was written and
    displayed, and the registration form ignored it. A setting whose help text
    lies is worse than a setting that does not exist."""
    from app.services import settings_store

    # Global: a specific ADOM can only create ITS own family, so the selector
    # would carry a single option and the test would prove nothing.
    login(client, admin_user_id(app), product="global")
    with app.app_context():
        want = settings_store.general().get("default_kind")
    body = client.get("/appliances/", follow_redirects=True).get_data(as_text=True)
    block = re.search(r'<select class="form-select fw-form-control" name="kind".*?</select>',
                      body, re.S)
    assert block, "the registration form's platform selector was not found"
    selected = re.findall(r'value="([^"]+)"\s+selected', block.group(0))
    assert selected == [want], f"preselected {selected}, expected [{want!r}]"
