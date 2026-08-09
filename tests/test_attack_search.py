"""WAF → Search Attack ID: the triage table, the detail panel, and the AI path
that can end in a rule carve-out.

Three failure modes shaped these guards, and each one was invisible to the
obvious test:

* **The table.** One column list drives both the match table and the "recent
  entries" fallback. Two lists would let the fallback quietly describe a
  different thing than the table it stands in for.
* **The panel.** ``attack_drawer.js`` never runs during a server-side test. The
  advisor chat shipped broken for exactly that reason -- one undefined
  identifier in a callback, on the line before the one that redraws the view.
  So the script is checked structurally here, the way ``test_advisor_stream``
  checks the chat's.
* **The carve-out.** Team rule 2 (never author on a template-managed profile)
  was enforced on the hand-typed form and NOT on the AI path, which reached the
  same store by a different door. A rule that holds on one path and not another
  is not a rule.
"""
from __future__ import annotations

import json
import os
import re

import pytest

from conftest import admin_user_id, login
from _js_guard import undefined_calls
from test_advisor_stream import _code_only

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
JS = os.path.join(REPO, "app", "static", "js", "attack_drawer.js")
TPL = os.path.join(REPO, "app", "templates", "attack_search", "index.html")
VIEW = os.path.join(REPO, "app", "views", "attack_search.py")
EXC_VIEW = os.path.join(REPO, "app", "views", "exceptions.py")


def _read(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _no_comments_js(src: str) -> str:
    """JavaScript with ``//`` and ``/* */`` comments removed, strings KEPT.

    The mirror image of ``_code_only``, and both are needed for different
    guards. ``_code_only`` strips strings too, so a guard about a CSS class
    name — which only ever appears inside a string literal — passes vacuously
    against it. That is not hypothetical: the first version of the
    objedit-handles guard did exactly that, and it "passed" while asserting
    nothing at all.

    One pointer, left to right: comments and string literals are mutually
    ambiguous, so a two-pass strip cannot be correct (an apostrophe inside a
    comment opens a "string" that swallows the rest of the file).
    """
    out = []
    i, n = 0, len(src)
    quote = None
    while i < n:
        ch = src[i]
        if quote:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(src[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in "'\"`":
            quote = ch
            out.append(ch)
            i += 1
            continue
        if ch == "/" and i + 1 < n and src[i + 1] == "/":
            while i < n and src[i] != "\n":
                i += 1
            continue
        if ch == "/" and i + 1 < n and src[i + 1] == "*":
            i += 2
            while i + 1 < n and not (src[i] == "*" and src[i + 1] == "/"):
                i += 1
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def test_the_comment_stripper_keeps_strings():
    """Tripwire for the helper above: if it ever starts eating string literals,
    the guards built on it go quiet instead of red."""
    stripped = _no_comments_js(
        "/* fw-drawer-close */\nvar a = 'atk-backdrop'; // fw-drawer-reload\n")
    assert "atk-backdrop" in stripped
    assert "fw-drawer-close" not in stripped
    assert "fw-drawer-reload" not in stripped


# --------------------------------------------------------------------------- #
#  1. the triage table                                                          #
# --------------------------------------------------------------------------- #
def test_table_columns_cover_what_triage_needs():
    """Attack type, sub type, policy, attacker IP and destination IP — the five
    an operator sorts on before opening anything."""
    from app.services import attack_log
    keys = [k for k, _ in attack_log.TABLE_COLUMNS]
    for key in ("main_type", "sub_type", "policy", "src", "dst"):
        assert key in keys, key


def test_both_tables_are_driven_by_the_same_column_list():
    """The match table and the miss fallback render from ``table_columns``; a
    hard-coded <th> in either is how they drift apart."""
    tpl = _read(TPL)
    assert tpl.count("{% for key, label in table_columns %}") >= 3, (
        "each table header and body must iterate the shared column list")
    # The only literal <th> allowed is the empty action cell.
    literals = re.findall(r"<th(?![^>]*style=\"width:1%\")[^>]*>([A-Za-z][^<{]*)</th>", tpl)
    assert literals == [], literals


def test_column_labels_reach_the_page(app, client, monkeypatch):
    from app.extensions import db
    from app.models import Appliance
    from app.services import attack_log

    with app.app_context():
        a = Appliance(name="fw-t", host="192.0.2.13", port=443, username="u")
        a.password = "p"
        db.session.add(a)
        db.session.commit()
        aid = a.id

    row = {"msg_id": "000000031305", "policy": "pol-x", "main_type": "Allow Method",
           "sub_type": "N/A", "src": "192.0.2.1", "dst": "192.0.2.2",
           "action": "Alert_Deny", "rel_time": "2026-08-08 00:00:00"}
    monkeypatch.setattr(attack_log, "search_by_msg_id", lambda ap, m: [row])

    login(client, admin_user_id(app))
    r = client.get("/waf/attack-search/?q=000000031305&appliance_id=%d" % aid)
    html = r.get_data(as_text=True)
    assert r.status_code == 200
    for label in ("Attack Type", "Sub Type", "Policy", "Source IP", "Destination IP"):
        assert "<th>%s</th>" % label in html, label
    assert "192.0.2.1" in html and "192.0.2.2" in html


# --------------------------------------------------------------------------- #
#  2. the slide-over panel                                                      #
# --------------------------------------------------------------------------- #
def test_js_is_not_vacuously_empty():
    """Anti-vacuity tripwire. Every structural guard below is a NEGATIVE
    assertion over stripped source, and a negative assertion over an empty
    string always passes. A stripper bug once collapsed 18 KB to 168 bytes and
    took a whole guard file down with it, silently."""
    code = _code_only(_read(JS))
    assert len(code) > 4000, len(code)
    assert "addEventListener" in code


def test_every_function_the_panel_calls_is_defined_in_it():
    """The general shape of the bug that shipped the chat broken: a call
    resolving to nothing, killing the callback at that line and taking the rest
    of the flow with it.

    The checker lives in ``tests/_js_guard.py`` — one implementation, because
    the two copies this file and ``test_attack_ask_field`` used to carry drifted
    together out of step with the script and both failed against correct code.
    """
    missing = undefined_calls(_code_only(_read(JS)))
    assert not missing, missing


def test_panel_avoids_the_objedit_drawer_handles():
    """``objedit_drawer.js`` is loaded on every page and binds delegated
    handlers to ``.fw-drawer-close`` / ``.fw-drawer-reload``. Reusing those
    class names lets ITS ``pop()`` tear down a panel that is not on its stack,
    which removes the panel and leaves this module's backdrop on screen — a
    dead grey overlay with nothing to close it."""
    # Comments stripped, STRINGS KEPT — the class names live in string
    # literals, so ``_code_only`` (which strips both) would make every
    # assertion here pass vacuously. The positive assertion below is the
    # tripwire that proves the strings survived the strip.
    code = _no_comments_js(_read(JS))
    assert "atk-backdrop" in code, "the backdrop needs its own handle to be findable"
    assert "fw-drawer-close" not in code
    assert "fw-drawer-reload" not in code


def test_panel_renders_from_the_page_data_not_a_second_fetch():
    tpl = _read(TPL)
    assert 'id="atk-rows-data"' in tpl
    assert 'id="atk-page-data"' in tpl
    assert "|tojson" in tpl, "row data must be JSON-encoded, not interpolated raw"


def test_rows_are_clickable_and_the_script_is_linked():
    tpl = _read(TPL)
    assert "data-atk-index=" in tpl
    assert "attack_drawer.js" in tpl


# --------------------------------------------------------------------------- #
#  3. the AI path                                                               #
# --------------------------------------------------------------------------- #
def test_analysis_reads_the_entry_from_the_device_not_the_request():
    """The single most important property of ``/analyze``: the evidence comes
    off the appliance. If a browser could post the row, it could fabricate an
    "attack" and have a carve-out drafted from it — evidence supplied by the
    accused."""
    src = _code_only_py(_read(VIEW))
    assert "attack_log.search_by_msg_id(appliance,msg_id)" in _flat(src)
    body_keys = set(re.findall(r"body\.get\('([a-z_]+)'\)", src))
    # Control keys only — things that say WHICH entry and WHAT to do with it.
    assert body_keys <= {
        "appliance_id", "msg_id", "payload", "clone_wpp", "new_name",
        "field", "resolve_ptr", "exc_type", "fields", "verdict", "risk",
        "justification", "target", "apply", "create_container",
        # deep-clone controls (1.9.1): which blocked children to clone anyway
        # and the operator's acknowledgement of a partial clone. Both say WHAT
        # TO DO, not what the entry contained.
        "clone_anyway", "acknowledge",
        # /ask-field: the operator's own question and the thread it continues.
        # Both are control keys — neither is a field OF the entry, which is
        # what the guard below actually forbids.
        "question", "conversation_id",
    }, sorted(body_keys)
    assert "row" not in body_keys


def test_no_endpoint_takes_a_log_field_value_from_the_browser():
    """The allowlist above is the shape of the rule; this is the rule.

    Every carve-out path re-reads the entry from the appliance, so no route may
    take a field of that entry from the request body — a client that supplies
    the URL, the signature id or the source address is a client authoring the
    exception SATOM would then attribute to the device's own evidence.

    Stated over the field names rather than over a fixed allowlist because the
    allowlist grows with every new control key, and the day someone adds
    ``body.get('http_url')`` it would grow to cover that too.
    """
    from app.services import attack_log as al
    src = _code_only_py(_read(VIEW))
    body_keys = set(re.findall(r"body\.get\('([a-z_]+)'\)", src))
    row_fields = {k for k, _ in al.PRIMARY_FIELDS} | {k for k, _ in al.TABLE_COLUMNS}
    # ``msg_id`` is the exception that proves it: it names WHICH entry to read,
    # and is validated as digits before it is used as a lookup key.
    leaked = (body_keys & row_fields) - {"msg_id"}
    assert leaked == set(), leaked


def test_selected_scope_fields_are_names_not_values():
    """``body['fields']`` carries field NAMES the operator ticked; the values
    behind them come from the device-read row. Feeding the browser's own values
    into the payload would reintroduce exactly the hole the re-read closes."""
    src = _code_only_py(_read(VIEW))
    assert "attack_carveout.build(row,exc_type,fields)" in _flat(src)


def _code_only_py(src: str) -> str:
    """Python source with comments and docstrings dropped, via the AST.

    Same reason as the JS stripper: this file's guards name the very strings
    they forbid, so a raw grep matches the prose that EXPLAINS the guard. Eight
    times now in this repo.

    The AST is used rather than a token filter because the token filter written
    first was wrong in a way that made guards weaker, not louder: its "a string
    right after a newline is a docstring" heuristic also deleted dict-literal
    KEYS, so ``{'payload': ...}`` lost its key and a guard looking for
    ``payload`` would have failed on correct code — or, worse, a guard looking
    for its absence would have passed on broken code. ``ast.unparse`` drops
    comments by construction (they are not in the tree) and docstrings are
    removed explicitly.
    """
    import ast
    tree = ast.parse(src)
    for node in ast.walk(tree):
        body = getattr(node, "body", None)
        if not isinstance(body, list) or not body:
            continue
        if not isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef,
                                 ast.AsyncFunctionDef)):
            continue
        first = body[0]
        if (isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant)
                and isinstance(first.value.value, str) and len(body) > 1):
            del body[0]
    return ast.unparse(tree)


def _flat(text: str) -> str:
    """Whitespace-free view, for needles that must survive re-formatting.

    ``ast.unparse`` normalises spacing, so ``f(a, msg_id)`` may come back
    spaced differently than it was written. Asserting on the flattened form
    tests the CALL, not the formatting."""
    return re.sub(r"\s+", "", text)


def test_prompt_carries_the_real_fortiweb_field_names(app):
    """A model handed only type keys invents field names, the payload fails
    validation, and the draft is dropped SILENTLY — the reply describes a
    carve-out and the panel shows no button. Observed live 2026-08-08:
    ``{method, url_pattern}`` where FortiWeb wants ``{request-type,
    request-file, allow-request}``."""
    with app.app_context():
        from app.views.attack_search import _type_specs
        spec = _type_specs()
    assert "allow_method_exception_item" in spec
    assert "request-file*" in spec, "required fields must be marked"
    assert "allow-request" in spec
    assert "method," not in spec.replace("http-method,", "")


def test_verdict_and_risk_are_read_not_inferred():
    from app.views.attack_search import _parse_judgement
    assert _parse_judgement("VERDICT: false-positive\nRISK: low\n") == (
        "false-positive", "low")
    # Absent → empty, never a cheerful default. "The model declined to judge"
    # and "the model judged it harmless" must not look the same on a screen
    # that gates a carve-out.
    assert _parse_judgement("it looks fine to me") == ("", "")
    # A value outside the vocabulary is not passed through as if it were one.
    assert _parse_judgement("VERDICT: probably-ok\nRISK: nil") == ("", "")


def test_unfenced_proposal_is_still_recognised():
    """Models drop the fence. The failure is invisible — prose describes a
    carve-out, no draft appears, nothing says why."""
    from app.services import advisor
    obj = {"kind": "waf_exception", "appliance_id": 1, "title": "t",
           "payload": {"exc_type": "x"}}
    fenced = "text\n```%s\n%s\n```\n" % (advisor.PROPOSAL_FENCE, json.dumps(obj))
    assert advisor.extract_proposal(fenced) == obj
    assert advisor.extract_proposal("blah\n%s\nmore" % json.dumps(obj)) == obj
    # A fenced block that does not parse stays an error: fencing is an explicit
    # statement of intent, so garbage inside one is not an invitation to hunt.
    assert advisor.extract_proposal("```%s\n{nope}\n```\n%s" % (
        advisor.PROPOSAL_FENCE, json.dumps(obj))) is None
    # Random JSON in prose is not a proposal.
    assert advisor.extract_proposal('here is {"a": 1} for you') is None
    assert advisor.extract_proposal('{"kind": "waf_exception"}') is None


# --------------------------------------------------------------------------- #
#  4. the carve-out gate                                                        #
# --------------------------------------------------------------------------- #
def test_apply_proposal_refuses_a_template_managed_profile(app, monkeypatch):
    """Rule 2 on the AI path. Before this, an AI proposal was the EASIER route
    to a carve-out on a template than the manual form, which 403s."""
    from app.extensions import db
    from app.models_advisor import AdvisorConversation, AdvisorProposal
    from app.services import advisor, wpp_exceptions

    monkeypatch.setattr(wpp_exceptions, "template_lock_error",
                        lambda n: "locked!" if n == "WPP-Template" else "")
    with app.app_context():
        from app.models import Appliance
        ap = Appliance(name="fw-lock", host="192.0.2.13", port=443, username="u")
        ap.password = "p"
        db.session.add(ap)
        conv = AdvisorConversation(title="t", username="admin")
        db.session.add(conv)
        db.session.commit()
        aid = ap.id
        prop = AdvisorProposal(
            conversation_id=conv.id, kind="waf_exception", appliance_id=aid,
            title="t", rationale="r",
            payload=json.dumps({"exc_type": "geo_ip_exception_member_item",
                                "wpp_mkey": "WPP-Template", "policies": ["p"],
                                "fields": {"ip": "1.2.3.4"}}))
        db.session.add(prop)
        db.session.commit()
        with pytest.raises(ValueError, match="locked"):
            advisor.apply_proposal(prop, applied_by="tester")
        assert prop.status == "pending", "a refused proposal stays pending"


def test_clone_is_never_implicit():
    """The clone is a real device write. It happens only when the operator
    asked for it IN THAT CALL — a 409 that silently cloned would be a config
    change nobody approved."""
    src = _code_only_py(_read(VIEW))
    assert "body.get('clone_wpp')" in _flat(src)
    i_ask = src.index("clone_wpp")
    i_do = src.index("clone_and_rebind")
    assert i_ask < i_do, "the explicit ask must gate the write, not follow it"


def test_both_carve_out_pages_share_one_clone_implementation():
    """Two copies of the rules that protect a shared profile agree on the day
    they are written and diverge on the first change."""
    exc = _code_only_py(_read(EXC_VIEW))
    assert "ClonePlanner" not in exc, "the Exceptions view must delegate the clone"
    assert "wpp_clone_flow.clone_and_rebind" in exc
    view = _code_only_py(_read(VIEW))
    assert "wpp_clone_flow.clone_and_rebind" in view


def test_derived_clone_name_follows_the_naming_catalog(app):
    with app.app_context():
        from app.services import wpp_clone_flow
        assert wpp_clone_flow.derive_name("pol-satom-lab") == "wpp-pol-satom-lab"
        assert wpp_clone_flow.derive_name("") == ""


def test_apply_records_both_what_was_proposed_and_what_was_approved():
    """Different facts. An auditor asking "what did the model suggest" and
    "what did the human approve" must not get one answer."""
    src = _code_only_py(_read(VIEW))
    assert "proposed_payload" in src
    assert "applied_payload" in src
    assert "adapted" in src


def test_dismissal_is_recorded_not_deleted():
    src = _code_only_py(_read(VIEW))
    assert "attack_search.exception_dismiss" in src
    assert "advisor.dismiss_proposal" in src


def test_write_endpoints_require_config_write():
    """The AI must not be a cheaper permission than typing it in by hand."""
    src = _read(VIEW)
    for route in ("apply", "dismiss"):
        m = re.search(r"@bp\.route\('/proposal/<int:pid>/%s'.*?\ndef " % route,
                      src, re.DOTALL)
        assert m, route
        assert "require_permission('config_write')" in m.group(0), route


def test_analyze_requires_advisor_use():
    src = _read(VIEW)
    m = re.search(r"@bp\.route\('/analyze'.*?\ndef ", src, re.DOTALL)
    assert m and "require_permission('advisor.use')" in m.group(0)


# --------------------------------------------------------------------------- #
#  6. timestamps and form layout                                                #
# --------------------------------------------------------------------------- #
def _no_comments_tpl(src: str) -> str:
    """Template source with Jinja ``{# #}`` and HTML ``<!-- -->`` comments gone.

    Same reason as the two strippers above, for the third language in this
    feature: the guards below name the very attribute values they forbid, and
    the template comments that EXPLAIN the fix name them too. A raw grep would
    match the explanation and report a regression that is not there.
    """
    out = re.sub(r"\{#.*?#\}", " ", src, flags=re.S)
    return re.sub(r"<!--.*?-->", " ", out, flags=re.S)


def test_the_template_comment_stripper_is_not_vacuous():
    """Anti-vacuity tripwire for the stripper the layout guards depend on. Every
    one of them is a negative assertion, and a negative assertion over an empty
    string passes while proving nothing."""
    stripped = _no_comments_tpl(_read(TPL))
    assert len(stripped) > 3000, len(stripped)
    assert "align-items" in stripped, "the stripper ate the markup, not just the prose"
    assert "{# " not in stripped and "-->" not in stripped


def test_rel_time_is_epoch_seconds_not_a_date():
    """The premise the formatter rests on. FortiWeb sends ``rel_time`` as Unix
    epoch seconds in a STRING; if a firmware ever starts sending a formatted
    date there, ``local_time`` falls through to the raw value and this guard is
    the note explaining why the column stopped converting."""
    from app.services import attack_log
    assert attack_log.TIME_FIELD == "rel_time"
    assert attack_log.local_time({"rel_time": "1786181039"}).startswith("2026-08-08")


def test_epoch_is_localized_through_the_configured_timezone(app, monkeypatch):
    """The whole point: the column shows the admin's timezone, not UTC and not
    the appliance's. ``rel_time`` used to be printed raw — a ten-digit number
    under a heading that says Date/Time."""
    from app.services import attack_log, settings_store

    with app.app_context():
        base = dict(settings_store.general())
        monkeypatch.setattr(settings_store, "general",
                            lambda: dict(base, timezone="Europe/Zurich"))
        assert attack_log.local_time({"rel_time": "1786181039"}) == \
            "2026-08-08 11:23:59 CEST"


def test_the_timezone_is_read_not_hardcoded(app, monkeypatch):
    """Two different settings must produce two different strings. A formatter
    that hardcodes one zone passes every single-timezone assertion above."""
    from app.services import attack_log, settings_store

    with app.app_context():
        base = dict(settings_store.general())
        seen = {}
        for tz in ("UTC", "Europe/Zurich", "America/Mexico_City"):
            monkeypatch.setattr(settings_store, "general",
                                lambda tz=tz: dict(base, timezone=tz))
            seen[tz] = attack_log.local_time({"rel_time": "1786181039"})
        assert len(set(seen.values())) == 3, seen
        assert seen["UTC"].startswith("2026-08-08 09:23:59")


def test_a_value_that_is_not_an_epoch_is_shown_as_is(app):
    """Degrade to the device's own answer rather than invent a date for it. A
    formatter that raises takes the whole result table down with it."""
    from app.services import attack_log

    with app.app_context():
        assert attack_log.local_time({"rel_time": "not-a-time"}) == "not-a-time"
        assert attack_log.local_time({"rel_time": "1786181039553648710"}) == \
            "1786181039553648710"          # nanoseconds, not seconds
        assert attack_log.local_time({}) == ""
        assert attack_log.local_time({"rel_time": "N/A"}) == ""


def _epoch_row():
    return {"msg_id": "000000031305", "policy": "pol-x", "main_type": "Allow Method",
            "sub_type": "N/A", "src": "192.0.2.1", "dst": "192.0.2.2",
            "action": "Alert_Deny", "rel_time": "1786181039"}


def _appliance(app):
    from app.extensions import db
    from app.models import Appliance
    with app.app_context():
        a = Appliance(name="fw-tz", host="192.0.2.13", port=443, username="u")
        a.password = "p"
        db.session.add(a)
        db.session.commit()
        return a.id


def test_the_table_never_prints_the_raw_epoch(app, client, monkeypatch):
    """End-to-end over the rendered page, because the defect lived between a
    correct service and a correct template: both halves were right and the
    column still showed a number."""
    from app.services import attack_log

    aid = _appliance(app)
    monkeypatch.setattr(attack_log, "search_by_msg_id", lambda ap, m: [_epoch_row()])
    login(client, admin_user_id(app))
    html = client.get("/waf/attack-search/?q=000000031305&appliance_id=%d" % aid) \
                 .get_data(as_text=True)
    body = re.search(r'id="atk-results">.*?</table>', html, re.S).group(0)
    assert "1786181039" not in body, "the epoch reached the Date/Time column"
    assert "2026-08-08" in body


def test_the_panel_is_handed_the_same_strings_as_the_table(app, client, monkeypatch):
    """One localization, two consumers. Formatting again in the browser is how
    a panel comes to disagree with the row it was opened from."""
    from app.services import attack_log

    aid = _appliance(app)
    monkeypatch.setattr(attack_log, "search_by_msg_id", lambda ap, m: [_epoch_row()])
    login(client, admin_user_id(app))
    html = client.get("/waf/attack-search/?q=000000031305&appliance_id=%d" % aid) \
                 .get_data(as_text=True)
    page = json.loads(re.search(r'id="atk-page-data">(.*?)</script>', html, re.S).group(1))
    body = re.search(r'id="atk-results">.*?</table>', html, re.S).group(0)
    assert page["row_times"], "the panel was left to format the epoch itself"
    assert page["time_field"] == "rel_time"
    assert page["row_times"][0] in body, "table and panel show different times"


def test_the_panel_does_not_localize_in_the_browser():
    """No second notion of 'what time is it' in JS. The timezone is a server-side
    setting; a browser-side conversion would follow the OPERATOR's machine and
    quietly disagree with every other timestamp in the product."""
    code = _code_only(_read(JS))
    for banned in ("toLocaleString", "toLocaleDateString", "toLocaleTimeString",
                   "Intl.DateTimeFormat", "getTimezoneOffset"):
        assert banned not in code, banned


def test_the_time_column_name_has_one_definition():
    """``attack_log.TIME_FIELD`` decides which column is the timestamp. A second
    copy of the literal in the template or the panel is a rename waiting to
    half-apply."""
    assert "rel_time" not in _no_comments_tpl(_read(TPL))
    assert "rel_time" not in _no_comments_js(_read(JS))


def test_the_search_form_aligns_from_the_top():
    """Labels and controls on one line. ``align-items-end`` pinned each column's
    last element to a shared baseline, and only the Attack ID column ends in a
    help line — so its label and its input both sat a line above the appliance
    picker's."""
    tpl = _no_comments_tpl(_read(TPL))
    form = re.search(r"<form method=\"get\".*?</form>", tpl, re.S).group(0)
    assert "align-items-start" in form
    assert "align-items-end" not in form
    # The submit column needs its own blank label or it rides up to the label row.
    submit_col = form[form.index('<button type="submit"') - 400:]
    assert "form-label" in submit_col[:400], (
        "the Search button has no label-height spacer above it")
