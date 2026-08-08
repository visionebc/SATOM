"""Guards for three defects the Attack-ID panel shipped with (2026-08-08).

All three were reported from one screen, ``/waf/attack-search/`` on entry
``000000004106`` of fortiweb08 — an **Allow Method** block on ``GET /``:

1. **"Explain this field" did nothing.** ``wireBody()`` bound its delegated
   handlers to ``.atk-body``, which ``open()`` refills but never replaces, so
   every entry opened added one more handler to the same node. Two handlers
   toggled the intelligence row open and shut inside a single click: the panel
   worked on the first entry, was dead on the second, worked on the third. The
   guard here is the general form — the per-open wiring function may not bind
   anything to the persistent body — because "it works when I test one row" is
   exactly how it passed review.

2. **An Allow Method carve-out could not carry a method.** ``allow-request`` is
   the allow list; the builder never set it, and ``http_method`` was not a
   scoper, so ticking *Method* — the obvious move on a screen titled *Allow
   Method* — was answered with "FortiWeb has nowhere to put it". It has exactly
   somewhere to put it: ``/api/v2.0/cmdb/waf/allow-method-exceptions/
   allow-method-exception-list`` on the live box returns
   ``"allow-request": "delete put "``. Worse than the rejection was the payload
   that DID validate: ``{request-type, request-file}`` with no allow list, which
   FortiWeb stores, applies, and which allows nothing.

3. **Every status badge on the page was unstyled.** ``fw-badge-ok`` /
   ``-warn`` / ``-crit`` / ``-neutral`` are not classes that exist;
   ``fortiweb.css`` defines ``-success`` / ``-warning`` / ``-danger`` /
   ``-secondary``. The base ``.fw-badge`` sets no colour at all, so a
   ``true-attack`` verdict and a ``false-positive`` verdict rendered
   identically. This is the second time this product has shipped a badge that
   states a severity nobody can read (``safeguards`` §9m), so the guard is
   repo-wide rather than local to this page.
"""
from __future__ import annotations

import glob
import os
import re

import pytest

from app.services import attack_carveout as cv
from app.services import wpp_exceptions as store
from test_attack_carveout import _appliance, _as_admin, _wired
from test_attack_search import JS, TPL, _no_comments_js, _read

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CSS = os.path.join(REPO, "app", "static", "css", "fortiweb.css")

#: The reported entry, as ``search_by_msg_id`` returned it from fortiweb08.
ALLOW_ROW = {
    "msg_id": "000000004106", "main_type": "Allow Method", "sub_type": "N/A",
    "policy": "pol-shop-cms", "src": "192.0.2.7", "dst": "192.0.2.246",
    "http_host": "192.0.2.92", "http_url": "/", "http_method": "get",
    "action": "Alert_Deny",
    "msg": "Allow Method Violation - HTTP request method (GET) is not allowed.",
}

ALLOW_TYPE = "allow_method_exception_item"


# --------------------------------------------------------------------------- #
#  2. The allow list                                                           #
# --------------------------------------------------------------------------- #
def test_allow_method_payload_carries_the_rejected_method():
    """Without ``allow-request`` the exception allows nothing at all."""
    built = cv.build(ALLOW_ROW, ALLOW_TYPE, ["http_url"])
    assert built["payload"]["allow-request"] == "get"
    assert built["payload"]["request-file"] == "/"
    assert built["errors"] == []


def test_allow_request_is_the_token_form_the_device_uses():
    """fortiweb08 stores ``"delete put "`` — lowercase, space separated.

    A payload of ``GET`` is not the same string as ``get`` to the box, and the
    log row reports the method in whatever case the request used.
    """
    built = cv.build(dict(ALLOW_ROW, http_method="POST"), ALLOW_TYPE, ["http_url"])
    assert built["payload"]["allow-request"] == "post"


def test_method_is_taken_from_the_entry_without_being_ticked():
    """It is the SUBJECT of the carve-out, not a narrowing of it."""
    built = cv.build(ALLOW_ROW, ALLOW_TYPE, ["http_url"])
    assert "http_method" in built["used"]
    assert cv.subject_for(ALLOW_TYPE, ALLOW_ROW)["value"] == "get"
    assert cv.subject_for("signature_filter_item", ALLOW_ROW) is None


def test_ticking_the_method_is_not_reported_as_unusable():
    """The reported symptom: ticking *Method* on an *Allow Method* exception
    was answered with "FortiWeb has nowhere to put it"."""
    built = cv.build(ALLOW_ROW, ALLOW_TYPE, ["http_url", "http_method"])
    assert [i["row_key"] for i in built["ignored"]] == []
    assert built["errors"] == []


def test_a_field_that_genuinely_cannot_scope_is_still_refused():
    """The fix widens the subject, not the door: an unrelated field is still
    reported rather than silently dropped."""
    built = cv.build(ALLOW_ROW, ALLOW_TYPE, ["http_url", "http_agent"])
    assert [i["row_key"] for i in built["ignored"]] == ["http_agent"]


def test_an_entry_with_no_method_fails_loudly():
    """Silence here is the dangerous answer: a stored row that allows nothing
    looks applied and leaves the request blocked."""
    built = cv.build(dict(ALLOW_ROW, http_method=""), ALLOW_TYPE, ["http_url"])
    assert "allow-request" not in built["payload"]
    assert any("allow-request" in e for e in built["errors"])


def test_the_allow_list_is_required_for_the_manual_form_too():
    """The carve-out builder is not the only author — the Exceptions page uses
    the same validator, and had the same hole."""
    assert "allow-request" in store.REQUIRED_FIELDS[ALLOW_TYPE]
    assert store.validate_payload(ALLOW_TYPE, {
        "request-type": "plain", "request-file": "/"})
    assert store.validate_payload(ALLOW_TYPE, {
        "request-type": "plain", "request-file": "/",
        "allow-request": "get"}) == []


# --------------------------------------------------------------------------- #
#  2b. Required scopes, and errors an operator can act on                      #
# --------------------------------------------------------------------------- #
def test_the_url_is_declared_required_not_offered_as_narrowing():
    scopers = {s["row_key"]: s for s in cv.scopers_for(ALLOW_TYPE)}
    assert scopers["http_url"]["required"] is True
    assert scopers["http_host"]["required"] is False


def test_every_required_scoper_actually_supplies_a_required_key():
    """Structural: ``required=True`` is a claim about the validator, so it is
    checked against the validator rather than trusted."""
    for exc_type, scopers in cv.SCOPERS.items():
        needed = set(store.REQUIRED_FIELDS.get(exc_type, ()))
        for s in scopers:
            if not s.required:
                continue
            payload = cv._assemble(ALLOW_ROW, exc_type, [s.row_key])[0]
            assert needed & {k for k, v in payload.items() if str(v).strip()}, (
                "%s marks %s required but it fills no required key"
                % (exc_type, s.row_key))


def test_a_missing_required_key_names_the_box_to_tick():
    """``'request-file' is required for this carve-out type`` is true and
    unactionable — the operator never typed ``request-file``."""
    built = cv.build(ALLOW_ROW, ALLOW_TYPE, [])
    joined = " ".join(built["errors"])
    assert "tick URL" in joined
    assert "(/)" in joined
    assert "is required for this carve-out type" not in joined


def test_the_remedy_is_derived_from_the_assembler_not_a_second_table():
    """A hand-written device-key → log-field map would drift from the code that
    builds the payload, and the copy that drifts is the one in the error.

    Proved by moving the payload: a type whose URL fills a DIFFERENT device key
    still gets a URL remedy, because the answer comes from running the real
    assembly.
    """
    row = {"msg_id": "1", "main_type": "HTTP Header Security",
           "http_url": "/api/v1/orders", "http_host": "shop.example.com"}
    built = cv.build(row, "http_header_security_exception_item", [])
    joined = " ".join(built["errors"])
    assert "request-url-pattern" in joined
    assert "tick URL" in joined
    assert "/api/v1/orders" in joined


def test_an_unsuppliable_key_does_not_send_the_operator_round_a_loop():
    built = cv.build(dict(ALLOW_ROW, http_method=""), ALLOW_TYPE, ["http_url"])
    joined = " ".join(built["errors"])
    assert "tick" not in joined
    assert "by hand" in joined


def test_the_forged_row_rule_still_holds():
    """The builder reads the entry, never the selection's claimed values."""
    built = cv.build(ALLOW_ROW, ALLOW_TYPE, ["http_url"])
    assert built["payload"]["request-file"] == "/"


# --------------------------------------------------------------------------- #
#  1. The listener that was bound once per open()                              #
# --------------------------------------------------------------------------- #
def _js_function(src: str, name: str) -> str:
    """The source of one top-level ``function name(...)`` in the module."""
    start = src.index("function %s(" % name)
    nxt = src.find("\n  function ", start + 1)
    body = src[start:nxt if nxt != -1 else len(src)]
    assert len(body) > 100, "extractor produced nothing for %s" % name
    return body


def test_the_function_extractor_is_not_vacuous():
    """A negative assertion over an empty string always passes. This is the
    tripwire that says the two guards below are reading real code."""
    code = _no_comments_js(_read(JS))
    assert "addEventListener" in _js_function(code, "ensureChrome")
    assert "querySelector" in _js_function(code, "wireBody")


def test_per_open_wiring_binds_nothing_to_the_persistent_body():
    """The general form of the bug: ``open()`` refills ``.atk-body`` but never
    replaces it, so a listener attached from the per-open path survives and
    accumulates. An even number of them is indistinguishable from none."""
    code = _no_comments_js(_read(JS))
    assert "body.addEventListener" not in _js_function(code, "wireBody")


def test_the_delegated_handlers_live_where_the_body_is_created():
    chrome = _no_comments_js(_read(JS))
    chrome = _js_function(chrome, "ensureChrome")
    assert "body.addEventListener" in chrome
    assert ".atk-i" in chrome and ".atk-pick" in chrome


def test_the_delegated_click_reads_the_current_row_at_event_time():
    """It cannot close over a row any more — there is no per-open rebind left
    to capture one, so a captured row would be permanently the first entry."""
    chrome = _js_function(_no_comments_js(_read(JS)), "ensureChrome")
    assert "ROWS[current]" in chrome


# --------------------------------------------------------------------------- #
#  3. Badges that name a colour nobody defined                                 #
# --------------------------------------------------------------------------- #
def _defined_badges() -> set[str]:
    return set(re.findall(r"\.(fw-badge-[a-z0-9-]+)", _read(CSS)))


def _used_badges() -> dict[str, set[str]]:
    used: dict[str, set[str]] = {}
    for pattern in ("app/templates/**/*.html", "app/static/js/**/*.js"):
        for path in glob.glob(os.path.join(REPO, pattern), recursive=True):
            for name in re.findall(r"fw-badge-[a-z0-9-]+", _read(path)):
                used.setdefault(name, set()).add(os.path.relpath(path, REPO))
    return used


def test_the_badge_scan_finds_the_badges_that_are_there():
    """Anti-vacuity: a scan that matched nothing would make the guard below
    pass while asserting nothing."""
    used = _used_badges()
    assert len(used) >= 4
    assert "fw-badge-danger" in used


def test_every_badge_class_used_anywhere_is_defined_in_the_stylesheet():
    """``.fw-badge`` alone sets no background and no colour, so an undefined
    modifier is not a fallback — it is a severity rendered as plain text.

    Repo-wide on purpose: the whole product had exactly one offender, and it
    was the newest page.
    """
    defined = _defined_badges()
    orphans = {k: sorted(v) for k, v in _used_badges().items()
               if k not in defined}
    assert orphans == {}, "undefined badge classes: %r" % orphans


@pytest.mark.parametrize("name", ["ok", "warn", "crit", "neutral"])
def test_the_invented_names_are_gone_from_the_attack_id_surface(name):
    bad = re.compile(r"fw-badge-%s(?![-\w])" % name)
    assert not bad.search(_read(JS))
    assert not bad.search(_read(TPL))


def test_one_tick_that_fixes_two_keys_is_reported_once():
    """A URL supplies both ``request-type`` and ``request-file``. Two lines with
    the same remedy read as two problems and double the apparent distance to a
    valid carve-out."""
    errors = cv.build(ALLOW_ROW, ALLOW_TYPE, [])["errors"]
    assert errors == [
        "request-type and request-file are missing — tick URL (/) in the "
        "Entry table above"]


def test_the_options_endpoint_hands_the_subject_to_the_panel(app, client,
                                                             monkeypatch):
    """The service knowing about the method is not enough — the panel only says
    so if the route sends it, and a ``None`` here is invisible from the
    service's own tests."""
    with app.app_context():
        aid = _appliance(app, "fw-subject")
        _wired(app, monkeypatch, {"pol-shop-cms": "wpp-solo"}, row=ALLOW_ROW)
        _as_admin(app, client)
        r = client.post("/waf/attack-search/options", json={
            "appliance_id": aid, "msg_id": "000000004106"})
        assert r.status_code == 200
        types = {t["exc_type"]: t for t in r.get_json()["types"]}
        subject = types[ALLOW_TYPE]["subject"]
        assert subject["value"] == "get"
        assert subject["label"] == "Method"
        assert types[ALLOW_TYPE]["scopers"][0]["required"] is True
