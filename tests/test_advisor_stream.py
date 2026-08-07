"""AI Advisor — streaming, cancellation and the UI wiring that shows it.

These guard the failure this file exists because of: the reply reached the
database and never reached the screen. The API test that "proved" the feature
worked asserted on ``/send``'s JSON, which was correct the whole time -- the
break was one undefined identifier in the browser, on the line right before
the one that redraws the thread. An endpoint test cannot see that, so the
guards here are split deliberately:

* **transport** -- the stream really is incremental, and says so in headers
  a reverse proxy will act on;
* **cancellation** -- Stop persists what was generated and records the call;
* **wiring** -- the page's script obeys the convention that makes the original
  bug impossible to write again.
"""
from __future__ import annotations

import io
import json
import os
import re

import pytest

from conftest import admin_user_id, login

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TPL = os.path.join(REPO, "app", "templates", "advisor", "index.html")
SRC = os.path.join(REPO, "app", "services", "advisor.py")
VIEW = os.path.join(REPO, "app", "views", "advisor.py")
UNIT = os.path.join(REPO, "deploy", "satom.service")


class _Reply:
    def __init__(self, text, prompt_tokens=None, completion_tokens=None):
        self.text = text
        self.raw = {}
        self.prompt_tokens = prompt_tokens
        self.completion_tokens = completion_tokens


def _seed(kind="ollama", external_on=False):
    from app.services import advisor
    key = f"p-{kind}"
    advisor.save_provider(key=key, kind=kind, label=key,
                          base_url="https://provider.example.net"
                          if kind != "ollama" else "http://127.0.0.1:11434",
                          model="m", api_key="k" if kind != "ollama" else None)
    advisor.set_flags(enabled_=True, external=external_on)
    return key


def _conv(app):
    from app.services import advisor
    return advisor.create_conversation("admin")


def _script(text: str) -> str:
    """The page's inline script body."""
    m = re.search(r"<script nonce=[^>]*>(.*?)</script>", text, re.DOTALL)
    assert m, "the advisor page has no inline script"
    return m.group(1)


def _executable(js: str) -> str:
    """Script with // comments removed.

    A guard that greps raw source matches the comment that EXPLAINS the guard.
    That has bitten this repo repeatedly; strip first, assert second."""
    return "\n".join(re.sub(r"//.*$", "", ln) for ln in js.split("\n"))


def _code_only(js: str) -> str:
    """Strip comments and string/template/regex literals in ONE pass.

    Two passes cannot work: comments and strings are mutually ambiguous. A
    first version stripped literals and then comments, and the apostrophe in a
    comment ("sibling\'s scope") opened a string that swallowed the next few
    thousand characters -- the script collapsed from 17,950 bytes to 168 and
    every guard built on it passed vacuously. One pointer, left to right, and
    whichever construct starts first wins.
    """
    out, i, n, prev = [], 0, len(js), ""
    while i < n:
        two = js[i:i + 2]
        if two == "//":
            j = js.find("\n", i)
            i = n if j < 0 else j
            out.append(" ")
            continue
        if two == "/*":
            j = js.find("*/", i + 2)
            i = n if j < 0 else j + 2
            out.append(" ")
            continue
        c = js[i]
        if c in "\'\"`":
            q, i = c, i + 1
            while i < n and js[i] != q:
                i += 2 if js[i] == "\\" else 1
            i += 1
            out.append('""')
            continue
        if c == "/" and prev in "(=,:[!&|?{};":
            j, closed = i + 1, False
            while j < n:
                if js[j] == "\\":
                    j += 2
                    continue
                if js[j] == "\n":
                    break
                if js[j] == "/":
                    closed = True
                    break
                j += 1
            if closed:
                i = j + 1
                while i < n and js[i].isalpha():
                    i += 1
                out.append("RE")
                continue
        out.append(c)
        if not c.isspace():
            prev = c
        i += 1
    return "".join(out)


def test_the_code_extractor_does_not_eat_the_script(app, client):
    """Anti-vacuity. Every guard below is an assertion about what is NOT in the
    code; if the extractor returns almost nothing they all pass and prove
    nothing. This is the tripwire for that."""
    login(client, admin_user_id(app))
    raw = _script(client.get("/advisor/").get_data(as_text=True))
    code = _code_only(raw)
    assert len(code) > 0.5 * len(raw), (
        "the extractor destroyed the script: %d -> %d bytes" % (len(raw), len(code)))
    assert "function sendFlow" in code and "AbortController" in code


# ---------------------------------------------------------------------------
# the wiring that broke
# ---------------------------------------------------------------------------

# The names the old version reached for across scopes. The convention now is
# that every DOM handle is an `el`-prefixed variable declared once at the top
# of the IIFE, so a bare use of any of these is the exact mistake returning.
_LEGACY_HANDLES = ("input", "btn", "thread", "box", "menu", "bubble0")

# A value that only ever enters the exchange through a tool result.
SECRET = "node-alpha-one.example-internal"


def test_no_dom_handle_is_referenced_as_a_bare_identifier(app, client):
    """The regression guard.

    ``input.value = ''`` sat inside a nested callback while ``var input``
    belonged to a sibling function. JavaScript resolves that to nothing, so the
    callback threw there and never reached the next line -- which was the one
    that redrew the thread. The reply was saved and invisible until reload.
    """
    login(client, admin_user_id(app))
    js = _executable(_script(client.get("/advisor/").get_data(as_text=True)))
    for name in _LEGACY_HANDLES:
        # a read or a write of the bare name, not a property (`x.input`) and
        # not part of a longer identifier (`elInput`, `inputs`)
        hits = re.findall(r"(?<![.\w$])" + name + r"(?![\w$])\s*(?:\.|=[^=])", js)
        assert not hits, f"bare DOM handle {name!r} used {len(hits)}x — use the el* handle"


def test_every_dom_handle_is_declared_once_at_the_top_of_the_iife(app, client):
    login(client, admin_user_id(app))
    js = _script(client.get("/advisor/").get_data(as_text=True))
    for handle in ("elThread", "elInput", "elSend", "elStop", "elProposals"):
        assert len(re.findall(r"\bvar %s\b" % handle, js)) == 1, \
            f"{handle} must be declared exactly once"


def test_the_thread_is_redrawn_after_every_send(app, client):
    """Whatever else the send flow does, it must end by asking the server for
    the conversation again. That call is what the original bug never reached."""
    login(client, admin_user_id(app))
    js = _executable(_script(client.get("/advisor/").get_data(as_text=True)))
    flow = js[js.index("function sendFlow("):]
    flow = flow[:flow.index("function beginSend(")]
    assert "loadConversation(cid)" in flow, "sendFlow never refreshes the thread"


def test_the_page_offers_a_stop_control_wired_to_an_abort(app, client):
    login(client, admin_user_id(app))
    body = client.get("/advisor/").get_data(as_text=True)
    assert 'id="adv-stop"' in body and 'data-act="stop"' in body
    js = _executable(_script(body))
    assert "AbortController" in js
    assert "inflight.abort()" in js


def test_the_page_shows_a_pending_reply_while_it_waits(app, client):
    """A send that goes quiet is indistinguishable from a broken one."""
    login(client, admin_user_id(app))
    js = _executable(_script(client.get("/advisor/").get_data(as_text=True)))
    for piece in ("beginPending", "tickPending", "setPhase"):
        # Definition AND call. A substring test passes on
        # `beginPending_DISABLED`; checking only the call site passes when the
        # definition was renamed out from under it -- which is the original bug
        # class, just with a function instead of a variable.
        assert re.search(r"function\s+%s\s*\(" % piece, js), \
            f"the thinking indicator part {piece} is not defined"
        assert re.search(r"(?<![\w$.])%s\s*\(" % piece, js.replace("function " + piece, "")), \
            f"the thinking indicator part {piece} is never called"
    assert "adv-dots" in js


# Words that take a parenthesis without being a call, plus the browser globals
# this script legitimately reaches for.
_JS_KEYWORDS = {"if", "for", "while", "switch", "catch", "return", "typeof",
                "function", "else", "do", "new", "delete", "void", "in", "of"}
_JS_GLOBALS = {"fetch", "setTimeout", "setInterval", "clearInterval",
               "clearTimeout", "AbortController", "TextDecoder", "Promise",
               "JSON", "Object", "Array", "String", "Number", "Boolean",
               "Date", "RegExp", "Error", "Math", "parseInt", "parseFloat",
               "isNaN", "confirm", "alert", "encodeURIComponent",
               "decodeURIComponent", "document", "window", "history"}


def test_every_function_the_script_calls_is_defined_in_it(app, client):
    """The general form of the bug this file exists for: reaching for a name
    that resolves to nothing. JavaScript does not complain until the line runs,
    and the line that ran was in a callback nobody was watching."""
    login(client, admin_user_id(app))
    js = _code_only(_script(client.get("/advisor/").get_data(as_text=True)))
    defined = set(re.findall(r"function\s+([A-Za-z_$][\w$]*)\s*\(", js))
    defined |= set(re.findall(r"var\s+([A-Za-z_$][\w$]*)\s*=\s*function", js))
    # parameters are definitions too -- a callback handed in as `onFrame` is
    # called by name and defined nowhere else
    for params in re.findall(r"function\s*[\w$]*\s*\(([^)]*)\)", js):
        defined |= {q.strip() for q in params.split(",") if q.strip()}
    called = set(re.findall(r"(?<![\w$.])([A-Za-z_$][\w$]*)\s*\(", js))
    unknown = called - defined - _JS_KEYWORDS - _JS_GLOBALS
    assert not unknown, f"called but never defined in this script: {sorted(unknown)}"


def test_the_reply_meta_reports_duration_and_tokens(app, client):
    login(client, admin_user_id(app))
    js = _executable(_script(client.get("/advisor/").get_data(as_text=True)))
    assert "duration_ms" in js
    assert "tokens not reported" in js, \
        "an unreported token count must be said, not printed as 0"
    assert "total_tokens" in js


# ---------------------------------------------------------------------------
# transport
# ---------------------------------------------------------------------------

def test_the_stream_tells_a_reverse_proxy_not_to_buffer(app, client):
    """nginx buffers proxied responses by default and this product's vhost is
    written by the installer, not carried in git — so the instruction has to
    ride on the response or it never reaches an existing installation."""
    from app.services import advisor

    with app.app_context():
        _seed()
        cid = _conv(app).id
    login(client, admin_user_id(app))

    from app.services import advisor as adv

    def fake_stream(kind, **kw):
        yield ("delta", "hi")
        yield ("done", _Reply("hi", 1, 2))

    with app.app_context():
        pass
    import app.services.advisor as m
    m._provider_stream = fake_stream
    r = client.post(f"/advisor/{cid}/send-stream", json={"text": "q"})
    assert r.status_code == 200
    assert r.headers["Content-Type"].startswith("text/event-stream")
    assert r.headers.get("X-Accel-Buffering") == "no"
    r.close()


def test_a_provider_that_cannot_run_fails_before_the_stream_opens(app, client):
    """Once the body has started the status is already 200; an unusable
    provider would only be reportable as an error frame every client would have
    to remember to handle."""
    from app.services import advisor

    with app.app_context():
        _seed(kind="anthropic", external_on=False)   # external switch off
        cid = _conv(app).id
    login(client, admin_user_id(app))
    r = client.post(f"/advisor/{cid}/send-stream", json={"text": "q"})
    assert r.status_code == 502
    assert r.headers["Content-Type"].startswith("application/json")
    assert "external" in r.get_json()["error"]


def test_the_engine_emits_status_then_deltas_then_done(app, monkeypatch):
    from app.services import advisor

    with app.app_context():
        _seed()
        conv = _conv(app)
        monkeypatch.setattr(advisor, "_provider_send",
                            lambda *a, **k: _Reply("the answer", 5, 7))
        kinds = [k for k, _ in advisor._run_exchange(conv.id, "admin", "q", [])]
        assert kinds[0] == "status"
        assert "delta" in kinds
        assert kinds[-1] == "done"


def test_a_stalled_provider_still_writes_a_heartbeat(app, monkeypatch):
    """During a cold model load the heartbeat is the ONLY traffic on the
    connection: it keeps a proxy read timeout from killing a healthy exchange,
    and it is how this process finds out the browser went away."""
    import time
    from app.services import advisor

    with app.app_context():
        _seed()
        conv = _conv(app)
        monkeypatch.setattr(advisor, "HEARTBEAT_SECONDS", 0.05)

        def slow(kind, **kw):
            time.sleep(0.35)
            yield ("delta", "late")
            yield ("done", _Reply("late"))

        monkeypatch.setattr(advisor, "_provider_stream", slow)
        kinds = [k for k, _ in advisor._run_exchange(conv.id, "admin", "q", [],
                                                      streaming=True)]
        assert "heartbeat" in kinds, "a silent exchange produced no keepalive"
        assert kinds[-1] == "done"


def test_streaming_delivers_the_reply_in_pieces(app, monkeypatch):
    from app.services import advisor

    with app.app_context():
        _seed()
        conv = _conv(app)

        def chunks(kind, **kw):
            for piece in ("a", "b", "c"):
                yield ("delta", piece)
            yield ("done", _Reply("abc", 1, 1))

        monkeypatch.setattr(advisor, "_provider_stream", chunks)
        got = [v for k, v in advisor._run_exchange(conv.id, "admin", "q", [],
                                                    streaming=True) if k == "delta"]
        assert got == ["a", "b", "c"], "the stream arrived as one lump"


# ---------------------------------------------------------------------------
# cancellation
# ---------------------------------------------------------------------------

def test_stopping_keeps_the_partial_and_records_the_call(app, monkeypatch):
    """Discarding a cancelled reply would throw away tokens that were really
    spent and leave the next page load showing nothing -- which reads as "it
    lost my answer", not as "I cancelled it"."""
    import time
    from app.services import advisor
    from app.models_advisor import AdvisorMessage, AdvisorRequestLog

    with app.app_context():
        _seed()
        conv = _conv(app)
        cid = conv.id

        def endless(kind, **kw):
            for i in range(10000):
                yield ("delta", "tok ")
                time.sleep(0.001)
            yield ("done", _Reply("never"))

        monkeypatch.setattr(advisor, "_provider_stream", endless)
        gen = advisor._run_exchange(cid, "admin", "q", [], streaming=True)
        seen = 0
        for kind, _ in gen:
            if kind == "delta":
                seen += 1
                if seen >= 5:
                    break
        gen.close()          # what an aborted HTTP connection does

        msg = (AdvisorMessage.query.filter_by(conversation_id=cid, role="assistant")
               .order_by(AdvisorMessage.id.desc()).first())
        assert msg is not None, "the partial reply was thrown away"
        assert msg.stopped is True
        assert msg.content.strip(), "a stopped reply must keep what it produced"

        log = (AdvisorRequestLog.query.filter_by(conversation_id=cid)
               .order_by(AdvisorRequestLog.id.desc()).first())
        assert log is not None and log.ok is False
        assert "stopped" in log.error


def test_a_stopped_reply_is_written_exactly_once(app, monkeypatch):
    """Note: the `if persisted` guard inside _persist is defense in depth,
    not something this proves -- the control flow already makes a second
    call unreachable, and a mutation that removes the guard survives. Said
    out loud rather than dressed up as a bite."""
    import time
    from app.services import advisor
    from app.models_advisor import AdvisorMessage

    with app.app_context():
        _seed()
        cid = _conv(app).id

        def endless(kind, **kw):
            while True:
                yield ("delta", "x")
                time.sleep(0.001)

        monkeypatch.setattr(advisor, "_provider_stream", endless)
        gen = advisor._run_exchange(cid, "admin", "q", [], streaming=True)
        for kind, _ in gen:
            if kind == "delta":
                break
        gen.close()
        gen.close()          # idempotent: a double close must not double-write
        n = AdvisorMessage.query.filter_by(conversation_id=cid, role="assistant").count()
        assert n == 1, f"expected one assistant row, found {n}"


# ---------------------------------------------------------------------------
# the safety properties must survive the new transport
# ---------------------------------------------------------------------------

def test_tool_output_is_still_redacted_on_the_streaming_path(app, monkeypatch):
    """The model asks for a tool and SATOM injects the answer, so a tool result
    is neither the operator's text nor an attachment they approved. Without
    this it walks around the preview they were shown."""
    from app.services import advisor

    with app.app_context():
        _seed(kind="anthropic", external_on=True)
        advisor.set_flags(tools=True)
        conv = _conv(app)

        sent = []
        calls = {"n": 0}

        def two_rounds(kind, *, messages, **kw):
            sent.append(messages)
            calls["n"] += 1
            if calls["n"] == 1:
                yield ("delta", "")
                yield ("done", _Reply('```satom-tool\n{"tool":"probe","args":{}}\n```'))
            else:
                yield ("delta", "done")
                yield ("done", _Reply("done"))

        monkeypatch.setattr(advisor, "_provider_stream", two_rounds)
        monkeypatch.setattr(advisor, "call_tool",
                            lambda name, args: {"host": SECRET})
        monkeypatch.setattr(advisor, "redact_with_count",
                            lambda t: ("<<REDACTED>>", 1))

        list(advisor._run_exchange(conv.id, "admin", "q", [], streaming=True))
        assert calls["n"] >= 2, "the tool round never happened"
        second = json.dumps(sent[1])
        # The ABSENCE of the raw value is the property. Asserting only that a
        # redaction marker appears somewhere is satisfied by the operator-text
        # redaction, which is a different code path -- so the tool result could
        # go out in the clear and the test would still pass.
        assert SECRET not in second, "tool output reached the provider unredacted"
        assert "REDACTED" in second


def test_both_send_paths_run_the_same_engine(app):
    """Two copies of the tool loop would drift the moment either changed."""
    import ast
    tree = ast.parse(io.open(SRC, encoding="utf-8").read())
    for fn in ("send_message", "stream_message"):
        node = next(n for n in tree.body
                    if isinstance(n, ast.FunctionDef) and n.name == fn)
        called = {c.func.id for c in ast.walk(node)
                  if isinstance(c, ast.Call) and isinstance(c.func, ast.Name)}
        assert "_run_exchange" in called, f"{fn} does not use the shared engine"


def test_the_blocking_facade_still_raises_on_a_provider_error(app, monkeypatch):
    from app.services import advisor
    from app.services.advisor_providers import ProviderError

    with app.app_context():
        _seed()
        conv = _conv(app)

        def boom(*a, **k):
            raise ProviderError("upstream exploded")

        monkeypatch.setattr(advisor, "_provider_send", boom)
        with pytest.raises(ProviderError):
            advisor.send_message(conv, "admin", "q", [])


def test_the_streamed_conversation_is_loaded_by_id_not_handed_over(app):
    """A streamed body runs after the view returned, so anything fetched during
    the request is detached by then. Learned live: the first version passed the
    ORM object in and died on the first lazy load."""
    import ast
    tree = ast.parse(io.open(SRC, encoding="utf-8").read())
    node = next(n for n in tree.body
                if isinstance(n, ast.FunctionDef) and n.name == "stream_message")
    args = [a.arg for a in node.args.args]
    assert args[:2] == ["app", "conv_id"], \
        "stream_message must take (app, conv_id, ...), not a live ORM object"
    assert any(isinstance(n, ast.YieldFrom) for n in ast.walk(node)), (
        "delegate with `yield from` so close() reaches the engine's persist "
        "path; a for-loop leaves that to the garbage collector")
    withs = [w for w in ast.walk(node) if isinstance(w, ast.With)]
    assert withs, "the stream must own its app context"


# ---------------------------------------------------------------------------
# timeout ordering
# ---------------------------------------------------------------------------

def test_the_worker_timeout_outlives_the_provider_timeout(app):
    """Inverted, a slow model has its worker killed first and the operator gets
    a dropped connection instead of the provider's own timed-out message: the
    diagnosable error replaced by the opaque one."""
    from app.services import advisor_providers as p

    unit = io.open(UNIT, encoding="utf-8").read()
    m = re.search(r"--timeout (\d+)", unit)
    assert m, "the unit no longer sets an explicit gunicorn timeout"
    assert int(m.group(1)) > p.DEFAULT_TIMEOUT, (
        "gunicorn --timeout %s must exceed the provider timeout %s"
        % (m.group(1), p.DEFAULT_TIMEOUT))


def test_every_provider_kind_can_stream(app):
    """A kind that only the blocking path supports would silently lose the
    chat's own send path."""
    from app.services import advisor_providers as p

    for kind in p.KINDS:
        assert hasattr(p, "stream_" + ("openai_compatible" if kind == "openai" else kind)), \
            f"no streaming transport for provider kind {kind!r}"
