"""The integration manual has to describe the API that actually ships.

``docs/api_v1.md`` is the only thing an external team reads before wiring an
automation against SATOM. Nothing *fails* when it goes stale -- and a manual
that quietly lost an endpoint looks exactly like a manual that is complete. The
failure that produces is not "the docs are a bit behind": a reader who cannot
find a capability concludes the product does not have it, and a reader who
cannot find an error code writes a client that treats it as success.

That is not hypothetical here. Until 2026-08-13 this page's opening paragraph
said *"Mutations happen only through pre-created Scheduled Actions"* while the
running API already accepted seven object-authoring routes, and its endpoint
table -- the page's own list of what exists -- named six of thirteen routes.

These guards pin three things to the code, not to prose:

* every ``/api/v1`` rule in the live URL map has a row in the manual;
* every object-write capability the model defines is named on the page;
* every error code the API modules can literally emit is in an error table.

The authority is the router and the source, never a second list kept by hand:
a duplicated list is how the first one drifts.
"""
from __future__ import annotations

import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
MANUAL = ROOT / "docs" / "api_v1.md"
API_DIR = ROOT / "app" / "api_v1"

#: Modules that turn a refusal into an HTTP body. Their literal codes are the
#: ones a client can actually receive.
CODE_SOURCES = [
    API_DIR / "waf.py",
    API_DIR / "adc.py",
    API_DIR / "routes.py",
    ROOT / "app" / "api_v1" / "auth.py",
    ROOT / "app" / "models_api_token.py",
    ROOT / "app" / "services" / "api_object_rules.py",
]

#: Codes that exist for a caller that cannot occur through the HTTP surface
#: (a programming mistake inside SATOM), with the reason each is exempt.
NOT_CLIENT_FACING = {
    # authorize_object() rejects a capability name the code passed in. Reachable
    # only by a SATOM bug, never by anything a token holder sends.
    "unknown_capability": "internal misuse of authorize_object()",
}


@pytest.fixture()
def manual() -> str:
    return MANUAL.read_text(encoding="utf-8")


def _norm(path: str) -> str:
    """Compare routes by shape, not by parameter name.

    ``/appliances/<int:id>`` and ``/appliances/<id>`` are the same endpoint; the
    manual should not have to spell Werkzeug converters, and a rename of a view
    argument is not a documentation defect.
    """
    return re.sub(r"<[^>]+>", "<>", path.rstrip("/")) or "/"


def _documented_routes(text: str) -> set[tuple[str, str]]:
    """(METHOD, normalised path) pairs from every table row in the manual."""
    found = set()
    for row in re.findall(r"^\|.*\|$", text, re.M):
        methods = re.findall(r"`(GET|POST|PUT|PATCH|DELETE)`", row)
        paths = re.findall(r"`(/[A-Za-z0-9_<>:/-]*)`", row)
        for m in methods:
            for p in paths:
                found.add((m, _norm(p)))
    return found


def _live_routes(app) -> set[tuple[str, str]]:
    live = set()
    for rule in app.url_map.iter_rules():
        path = str(rule)
        if not path.startswith("/api/v1"):
            continue
        for method in rule.methods - {"HEAD", "OPTIONS"}:
            live.add((method, _norm(path[len("/api/v1"):] or "/")))
    return live


# ---------------------------------------------------------------------------
# 1. Every route
# ---------------------------------------------------------------------------

def test_every_api_v1_route_has_a_row_in_the_manual(app, manual):
    missing = sorted(_live_routes(app) - _documented_routes(manual))
    assert not missing, (
        "routes exist but the manual does not list them: "
        + ", ".join(f"{m} {p}" for m, p in missing)
        + " -- add a row to docs/api_v1.md section 3")


def test_the_manual_does_not_advertise_a_route_that_is_gone(app, manual):
    """The opposite failure, and the worse one to debug: an integrator writes a
    client against a documented endpoint and gets 404 from a healthy service."""
    live = _live_routes(app)
    documented = {(m, p) for m, p in _documented_routes(manual)
                  # rows quoting device-side or non-API paths are not claims
                  # about /api/v1; only compare shapes the API could own
                  if p.startswith(("/ping", "/appliances", "/actions", "/waf", "/adc"))}
    ghosts = sorted(documented - live)
    assert not ghosts, (
        "the manual documents routes that do not exist: "
        + ", ".join(f"{m} {p}" for m, p in ghosts))


# ---------------------------------------------------------------------------
# 2. Every object-write capability
# ---------------------------------------------------------------------------

def test_every_object_write_capability_is_named_in_the_manual(manual):
    from app.models_api_token import EXPLICIT_ONLY_CAPABILITIES
    missing = sorted(c for c in EXPLICIT_ONLY_CAPABILITIES if c not in manual)
    assert not missing, (
        "capabilities an administrator must grant by name, absent from the "
        "manual: " + ", ".join(missing))


def test_the_manual_states_that_an_empty_capability_list_grants_nothing(manual):
    """The trap this API was built around. ``capabilities == []`` means
    *unrestricted* for catalog actions and *nothing* for object writes; a reader
    who carries the first meaning over grants a token they think is inert."""
    window = manual.split("## 2.")[0]
    flat = " ".join(window.split()).lower()
    assert "empty capability list" in flat and "no object writes" in flat, (
        "section 1 must say that an empty capability list authorises no object "
        "writes -- otherwise the default reads as 'everything'")


# ---------------------------------------------------------------------------
# 3. Every error code
# ---------------------------------------------------------------------------

def _emitted_codes() -> set[str]:
    codes: set[str] = set()
    pat_err = re.compile(r'_err\(\s*\d+\s*,\s*"([a-z_]+)"')
    pat_tuple = re.compile(r'\(\s*False\s*,\s*"([a-z_]+)"')
    for path in CODE_SOURCES:
        src = path.read_text(encoding="utf-8")
        codes |= set(pat_err.findall(src))
        codes |= set(pat_tuple.findall(src))
    return codes - set(NOT_CLIENT_FACING)


def test_every_error_code_the_api_emits_is_documented(manual):
    documented = set(re.findall(r"`([a-z_]+)`", manual))
    missing = sorted(_emitted_codes() - documented)
    assert not missing, (
        "error codes a client can receive but cannot look up: "
        + ", ".join(missing) + " -- add them to section 5 or section 7")


def test_the_exemption_list_is_not_a_way_to_hide_a_real_code():
    """An exemption without a reason is just a smaller guard. If a code that
    IS reachable gets parked here, this fails the moment the reason is empty."""
    for code, reason in NOT_CLIENT_FACING.items():
        assert reason.strip(), f"{code} is exempted with no reason"


# ---------------------------------------------------------------------------
# 4. Claims the page makes about itself
# ---------------------------------------------------------------------------

def test_the_manual_does_not_claim_mutations_are_actions_only(manual):
    """The sentence this suite was written for. It was true when written and
    became false the day object authoring shipped -- and being in the *first*
    paragraph, it is the part most readers never read past."""
    flat = " ".join(manual.split()).lower()
    assert "mutations happen only through" not in flat, (
        "the preamble still says mutations only happen through Scheduled "
        "Actions; object authoring (sections 6 and 7) contradicts it")


def test_the_manual_does_not_claim_to_be_generated(manual):
    """It is hand-written. Claiming generation tells a reader that a missing
    endpoint is impossible, which is the belief that lets one go missing."""
    flat = " ".join(manual.split()).lower()
    assert "generated from the live route definitions" not in flat


def test_both_object_authoring_sections_are_present(manual):
    for heading in ("## 6. WAF carve-outs", "## 7. FortiADC rules"):
        assert heading in manual, f"missing manual section: {heading}"
