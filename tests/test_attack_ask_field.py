"""Attack ID → "ask the AI about this field".

The panel already explained a field locally and already judged the whole entry
with the Advisor. What it could not do was let the operator ASK — in their own
words, about one element, with the answer landing under the explanation of that
element rather than in a separate page.

Three properties are worth guarding, and none of them is visible to a test that
only checks the endpoint returns 200:

* **The value is never taken from the browser.** Same rule the carve-out paths
  live by. A client that supplies the field value is a client supplying the
  evidence it then asks to have reasoned about.
* **This path answers; it cannot author.** The model is told not to draft a
  carve-out, no proposal is returned to the UI, and one drafted anyway is
  dismissed — otherwise it would sit ``pending``, visible on the Advisor page,
  approved by nobody and indistinguishable from a draft an operator requested.
* **Every analysis states its cost.** Engine, elapsed time, tokens. A missing
  token count reads as "not reported", never as zero, because those are
  different claims and only one of them was measured.
"""
from __future__ import annotations

import os
import re

from test_attack_search import (JS, TPL, VIEW, _code_only_py, _flat, _read,
                                _no_comments_js)
from _js_guard import undefined_calls
from test_advisor_stream import _code_only

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _fn_src(src: str, name: str) -> str:
    """One top-level function's source, bounded by the NEXT top-level def.

    Bounded by structure rather than by a character count: a window of "the
    next 2000 characters" silently starts including the following function the
    day this one grows, and the guard stops meaning what it says.
    """
    m = re.search(r"\ndef %s\(.*?(?=\ndef |\n@bp\.route|\Z)" % re.escape(name),
                  src, re.DOTALL)
    assert m, name
    return m.group(0)


# --------------------------------------------------------------------------- #
#  1. the evidence still comes off the device                                   #
# --------------------------------------------------------------------------- #
def test_ask_reads_the_entry_from_the_device_not_the_request():
    src = _code_only_py(_read(VIEW))
    fn = _fn_src(src, "ask_field")
    assert "_read_entry(appliance,msg_id)" in _flat(fn)
    # The field is named, then checked against the row that came off the box.
    assert "if key not in row" in _flat(fn).replace(",", ", ") or \
           "keynotinrow" in _flat(fn)


def test_ask_takes_no_log_field_value_from_the_browser():
    """The rule, stated over the field names rather than an allowlist — an
    allowlist grows to cover whatever was just added to it."""
    from app.services import attack_log as al
    src = _code_only_py(_read(VIEW))
    fn = _fn_src(src, "ask_field")
    body_keys = set(re.findall(r"body\.get\('([a-z_]+)'\)", fn))
    row_fields = {k for k, _ in al.PRIMARY_FIELDS} | {k for k, _ in al.TABLE_COLUMNS}
    assert (body_keys & row_fields) - {"msg_id"} == set(), sorted(body_keys)
    assert body_keys <= {"appliance_id", "msg_id", "field", "question",
                         "conversation_id"}, sorted(body_keys)


def test_the_prompt_fences_the_entry_as_untrusted():
    """The row carries strings an attacker chose. It is described, never
    obeyed — the same wrapper ``analyze`` uses."""
    src = _code_only_py(_read(VIEW))
    fn = _fn_src(src, "_ask_prompt")
    assert "advisor.wrap_untrusted" in fn
    assert "_row_digest(row)" in _flat(fn)


# --------------------------------------------------------------------------- #
#  2. it answers, it does not author                                            #
# --------------------------------------------------------------------------- #
def test_the_prompt_forbids_drafting_a_carve_out():
    src = _code_only_py(_read(VIEW))
    fn = _fn_src(src, "_ask_prompt")
    assert "advisor.PROPOSAL_FENCE" in fn
    assert "Do NOT draft" in fn


def test_ask_returns_no_proposal_to_the_ui():
    """No Accept button can exist for something the response never carries."""
    src = _code_only_py(_read(VIEW))
    fn = _fn_src(src, "ask_field")
    assert "proposal=" not in fn
    assert "_proposal_view" not in fn


def test_a_stray_proposal_is_dismissed_not_left_pending(app, monkeypatch):
    """Telling the model not to propose is not the same as trusting it not to.

    A ``pending`` row this page never renders is worse than a visible one: it
    is reachable from the Advisor page and looks exactly like a draft somebody
    asked for.
    """
    from app.extensions import db
    from app.models_advisor import AdvisorProposal
    from app.services import advisor
    from app.views import attack_search as view

    with app.app_context():
        conv = advisor.create_conversation("admin", title="Attack 1 — x — field questions")
        # Inserted directly rather than through ``create_proposal``: a stray row
        # is by definition one the schema gate did not vet, and routing the
        # fixture through that gate would test the gate instead of the sweep.
        db.session.add(AdvisorProposal(
            conversation_id=conv.id, kind="waf_exception", title="stray",
            payload="{}", rationale="", status="pending", created_by="model"))
        db.session.commit()
        n = view._quarantine_stray_proposals(conv, "admin")
        assert n == 1
        left = AdvisorProposal.query.filter_by(
            conversation_id=conv.id, status="pending").count()
        assert left == 0
        gone = AdvisorProposal.query.filter_by(conversation_id=conv.id).first()
        assert gone is not None, "dismissed, not deleted — the model did emit it"
        assert gone.status == "dismissed"


def test_the_ask_thread_is_never_the_analyze_thread(app):
    """If both landed in one conversation the quarantine above would dismiss
    the carve-out ``analyze`` drafted, and the operator's Accept button would
    go dead for no visible reason."""
    src = _code_only_py(_read(VIEW))
    ask = _fn_src(src, "_ask_conversation")
    analyze = _fn_src(src, "analyze")
    assert "field questions" in ask
    assert "field questions" not in analyze


# --------------------------------------------------------------------------- #
#  3. the conversation id is scoped to its owner                                #
# --------------------------------------------------------------------------- #
def test_a_conversation_id_cannot_reach_another_users_thread(app):
    from app.services import advisor
    from app.views import attack_search as view

    class _Appl:
        name = "fortiweb08"

    with app.app_context():
        theirs = advisor.create_conversation("carol", title="Carol's thread")
        got = view._ask_conversation("admin", theirs.id, _Appl(), "77")
        assert got.id != theirs.id, "reused another user's conversation"
        assert got.username == "admin"
        # And a legitimate reuse still works, or every question starts over.
        again = view._ask_conversation("admin", got.id, _Appl(), "77")
        assert again.id == got.id


def test_a_junk_conversation_id_starts_a_thread_instead_of_raising(app):
    from app.views import attack_search as view

    class _Appl:
        name = "fortiweb08"

    with app.app_context():
        conv = view._ask_conversation("admin", "not-a-number", _Appl(), "77")
        assert conv.id


# --------------------------------------------------------------------------- #
#  4. the question                                                              #
# --------------------------------------------------------------------------- #
def test_an_empty_question_becomes_a_real_one_and_is_recorded():
    """Recorded server-side, not "(default)": a reader of the audit trail has
    to be able to reconstruct what was actually asked."""
    from app.views import attack_search as view
    assert view.ASK_DEFAULT_QUESTION.strip()
    src = _code_only_py(_read(VIEW))
    fn = _fn_src(src, "ask_field")
    assert "ASK_DEFAULT_QUESTION" in fn
    assert "'question': question" in fn or "question=question" in _flat(fn)


def test_the_question_is_capped():
    from app.views import attack_search as view
    src = _code_only_py(_read(VIEW))
    fn = _fn_src(src, "ask_field")
    assert "ASK_MAX_QUESTION" in fn
    assert 0 < view.ASK_MAX_QUESTION <= 4000


def test_ask_requires_advisor_use_and_the_feature_switch():
    src = _read(VIEW)
    m = re.search(r"@bp\.route\('/ask-field'.*?\ndef ", src, re.DOTALL)
    assert m and "require_permission('advisor.use')" in m.group(0)
    fn = _fn_src(_code_only_py(src), "ask_field")
    assert "advisor.enabled()" in fn


# --------------------------------------------------------------------------- #
#  5. the panel                                                                 #
# --------------------------------------------------------------------------- #
def test_js_guards_are_not_vacuous():
    code = _code_only(_read(JS))
    assert len(code) > 4000, len(code)
    strings_kept = _no_comments_js(_read(JS))
    assert "atk-ask-send" in strings_kept, "the string stripper ate the classes"


def test_every_row_offers_both_an_explain_and_an_ask_control():
    code = _no_comments_js(_read(JS))
    m = re.search(r"function entryRows\(.*?\n  \}", code, re.DOTALL)
    assert m, "entryRows not found"
    assert "atk-i" in m.group(0)
    assert "atk-q" in m.group(0)
    assert "Ask the AI about this field" in m.group(0)


def test_the_ask_control_is_hidden_when_the_advisor_is_off():
    """A button that always 409s teaches the operator to distrust buttons."""
    code = _no_comments_js(_read(JS))
    m = re.search(r"function entryRows\(.*?\n  \}", code, re.DOTALL)
    assert "PAGE.ai_enabled" in m.group(0)


def test_the_answer_is_drawn_under_the_local_explanation():
    """Where the operator asked for it: below the explanation of the element,
    not instead of it and not in a second panel."""
    code = _no_comments_js(_read(JS))
    m = re.search(r"function renderCell\(.*?\n  \}", code, re.DOTALL)
    assert m, "renderCell not found"
    body = m.group(0)
    assert body.index("atk-icontent") < body.index("askHtml"), body


def test_the_thread_survives_the_row_being_collapsed():
    """State-then-render, not append-into-DOM. The cell's innerHTML is thrown
    away every time the row is redrawn."""
    code = _code_only(_read(JS))
    assert "askState" in code
    assert re.search(r"function askHtml\([^)]*\)\s*\{[^}]*askFor", code, re.DOTALL)


def test_the_ask_state_is_reset_when_a_second_entry_opens():
    """Otherwise entry B opens showing entry A's answers, attributed to B."""
    code = _code_only(_read(JS))
    m = re.search(r"function open\(index\).*?\n  \}", code, re.DOTALL)
    assert m and "askState={}" in _flat(m.group(0))


def test_the_panel_keeps_its_own_drawer_handles():
    code = _no_comments_js(_read(JS))
    assert "fw-drawer-close" not in code
    assert "fw-drawer-reload" not in code


def test_every_function_the_panel_calls_is_defined_in_it():
    """Re-run here over the grown file: the chat shipped broken because one
    call resolved to nothing and killed its callback at that line.

    Same checker as ``test_attack_search`` — ``tests/_js_guard.py`` — rather
    than a second copy of the regexes.
    """
    missing = undefined_calls(_code_only(_read(JS)))
    assert not missing, missing


# --------------------------------------------------------------------------- #
#  6. cost: a logo, a token count and an elapsed time on EVERY analysis         #
# --------------------------------------------------------------------------- #
def test_one_cost_chip_implementation_not_two():
    """Two of them agree the day they are written and diverge on the first
    change to either — which is how this page ended up with two clocks."""
    code = _code_only(_read(JS))
    assert len(re.findall(r"function costChip\(", code)) == 1
    assert len(re.findall(r"function startClock\(", code)) == 1
    # Stated as "nowhere else formats a cost", not as a call count: a count
    # stays green while one render site quietly grows its own copy, which is
    # exactly the regression this guard exists for.
    #
    # Over the STRING-PRESERVING view. _code_only blanks literals, so the
    # " s" in this needle never survives it and the assertion would read 0 == 1
    # against perfect code — the ninth time a guard in this repo has been
    # written against the wrong stripper.
    strings = _no_comments_js(_read(JS))
    assert len(re.findall(r"toFixed\(1\)\s*\+\s*' s'", strings)) == 1, \
        "something outside costChip is formatting an elapsed time"
    # And each of the three render sites goes through it.
    for fn in ("judgementHtml", "intelHtml", "askHtml"):
        m = re.search(r"function %s\(.*?\n  \}" % fn, code, re.DOTALL)
        assert m and "costChip(" in m.group(0), fn


def test_the_cost_chip_carries_an_icon_tokens_and_a_time():
    code = _no_comments_js(_read(JS))
    m = re.search(r"function costChip\(.*?\n  \}", code, re.DOTALL)
    assert m, "costChip not found"
    body = m.group(0)
    assert "bi " in body or "bi-" in body, "no icon"
    assert "tokens" in body
    assert "duration_ms" in body


def test_missing_tokens_are_reported_as_missing_not_as_zero():
    """A gateway that omits the usage block did not report zero tokens. A
    confident 0 is a measurement the product never made."""
    code = _no_comments_js(_read(JS))
    m = re.search(r"function costChip\(.*?\n  \}", code, re.DOTALL)
    body = m.group(0)
    assert "tokens not reported" in body
    assert "time not reported" in body
    # Named explicitly, not just "some != null appears somewhere in here": the
    # duration check is also a != null, so a loose assertion stays green while
    # the TOKEN branch is swapped for a truthy test — and a truthy test reports
    # a genuine 0-token reply as "not reported", which is a different claim.
    assert "d.prompt_tokens != null" in body, body
    assert "d.completion_tokens != null" in body, body


def test_the_local_explanation_reports_its_own_cost_too():
    """"Everything shows a logo, tokens and a time" includes the path that
    spends none — and "no tokens" there is a fact, not an absence."""
    code = _no_comments_js(_read(JS))
    m = re.search(r"function intelHtml\(.*?\n  \}", code, re.DOTALL)
    assert m and "costChip" in m.group(0)
    assert "local: true" in m.group(0) or "local:true" in _flat(m.group(0))
    src = _code_only_py(_read(VIEW))
    assert "elapsed_ms" in _fn_src(src, "field_intel")


def test_a_failed_exchange_still_shows_what_it_cost():
    """A provider that burned forty seconds and then errored spent them."""
    code = _no_comments_js(_read(JS))
    m = re.search(r"function sendAsk\(.*?\n  \}\n", code, re.DOTALL)
    assert m, "sendAsk not found"
    body = m.group(0)
    # Both failure paths hand a cost to settle().
    assert len(re.findall(r"cost:\s*\{duration_ms", body)) == 2, body


def test_the_wait_has_a_running_clock():
    code = _no_comments_js(_read(JS))
    assert "atk-ask-clock" in code
    m = re.search(r"function sendAsk\(.*?\n  \}\n", code, re.DOTALL)
    assert "startClock(" in m.group(0)


def test_the_clock_is_stopped_on_every_exit():
    """A ticker left running writes into a detached node forever."""
    code = _code_only(_read(JS))
    m = re.search(r"function sendAsk\(.*?\n  \}\n", code, re.DOTALL)
    body = m.group(0)
    # One settle() owns the stop, and both outcomes go through it.
    assert body.count("stopClock(clockId)") == 1
    assert body.count("settle(") == 4, body


# --------------------------------------------------------------------------- #
#  7. wiring                                                                    #
# --------------------------------------------------------------------------- #
def test_the_page_is_told_the_ask_url():
    tpl = _read(TPL)
    assert "'ask_field_url': url_for('attack_search.ask_field')" in tpl
    code = _no_comments_js(_read(JS))
    assert "PAGE.ask_field_url" in code
    assert "/ask-field" not in code, "the URL is handed over, never built"


def test_the_handlers_are_delegated_once_on_the_stable_body():
    """open() replaces the body's innerHTML but never the body. Binding per
    open stacked one more handler each time — that is how "Explain this field"
    once toggled itself shut from the second entry onwards."""
    code = _code_only(_read(JS))
    m = re.search(r"function ensureChrome\(\).*?\n  \}\n", code, re.DOTALL)
    assert m, "ensureChrome not found"
    chrome = m.group(0)
    for handle in ("atk-ask-send", "atk-q", "atk-i"):
        assert handle in _no_comments_js(_read(JS))
    assert "sendAsk(" in chrome and "openAsk(" in chrome and "toggleIntel(" in chrome
    for fn in ("function wireBody", "function open("):
        seg = re.search(re.escape(fn) + r".*?\n  \}\n", code, re.DOTALL)
        assert "atk-ask-send" not in (seg.group(0) if seg else "")


def test_plain_enter_stays_a_newline():
    """The box is a textarea because a question about a URL or a payload needs
    more than one line."""
    code = _no_comments_js(_read(JS))
    assert "atk-ask-input" in code
    assert re.search(r"ev\.key\s*!==\s*'Enter'\s*\|\|\s*!\(ev\.ctrlKey\s*\|\|\s*ev\.metaKey\)",
                     code), "Ctrl/Cmd is not required to send"


# --------------------------------------------------------------------------- #
#  8. the click is the question — the answer arrives without a second gesture   #
# --------------------------------------------------------------------------- #
def test_the_click_asks_immediately():
    """Opening the thread fires the exchange; it does not just show a box.

    The operator asked for the Advisor to answer ON the click, with the box
    kept for their reply. A panel that opens an empty textarea instead looks
    identical in a screenshot and is a different product.
    """
    code = _no_comments_js(_read(JS))
    m = re.search(r"function openAsk\(.*?\n  \}\n", code, re.DOTALL)
    assert m, "openAsk not found"
    assert "sendAsk(" in m.group(0)


def test_the_automatic_ask_is_claimed_before_it_fires():
    """``asked`` is set BEFORE the call, not after it returns.

    Set afterwards, two clicks landing while the first request is in flight
    both pass the guard and both bill the provider for the same question.
    """
    code = _no_comments_js(_read(JS))
    body = re.search(r"function openAsk\(.*?\n  \}\n", code, re.DOTALL).group(0)
    assert body.index("asked = true") < body.index("sendAsk(")


def test_the_automatic_ask_is_never_retried():
    """One automatic exchange per field per opened entry — answer or error.

    An automatic retry against a provider that just failed spends tokens to
    reproduce a failure the operator can already read on screen, and it does it
    every time they collapse and reopen the row.
    """
    code = _no_comments_js(_read(JS))
    body = re.search(r"function openAsk\(.*?\n  \}\n", code, re.DOTALL).group(0)
    assert "!st.asked" in body
    seed = re.search(r"function askFor\(.*?\n  \}\n", code, re.DOTALL).group(0)
    assert "asked: false" in seed


def test_the_automatic_question_is_left_to_the_server():
    """openAsk sends no question text of its own.

    The default lives in the view so the audit row records the string the
    provider actually received. A browser-side default puts a question in the
    log that was never sent, and the two drift on the first edit to either.
    """
    code = _no_comments_js(_read(JS))
    body = re.search(r"function openAsk\(.*?\n  \}\n", code, re.DOTALL).group(0)
    assert "question" not in body
    assert "ASK_DEFAULT_QUESTION" in _read(VIEW)


def test_one_call_site_reaches_the_ask_endpoint():
    """Every ask — automatic or typed — goes through the path that stamps cost.

    A second call site would be a second exchange with no clock, no token count
    and no entry in ``items``: the automatic answer is precisely the one that
    would arrive unstamped, because it is the one nobody typed.
    """
    code = _no_comments_js(_read(JS))
    assert code.count("PAGE.ask_field_url") == 1
    sender = re.search(r"function sendAsk\(.*?\n  \}\n", code, re.DOTALL).group(0)
    assert "PAGE.ask_field_url" in sender
    assert "costChip(" in re.search(r"function askHtml\(.*?\n  \}\n",
                                    code, re.DOTALL).group(0)


def test_the_box_below_turns_into_a_reply_box():
    """Once an answer is on screen the control says Reply, not Ask.

    Same button wording before and after tells the operator the panel is still
    waiting for their opening question when it has in fact already answered.
    """
    code = _no_comments_js(_read(JS))
    ask = re.search(r"function askHtml\(.*?\n  \}\n", code, re.DOTALL).group(0)
    assert "st.items.length > 0" in ask
    assert "Reply" in ask
    assert "leave it empty" not in ask
