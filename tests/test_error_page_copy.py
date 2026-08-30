"""Guard: the 500 page's Copy button must never claim success it did not have,
and must never fail in a way the operator cannot report.

The original handler was ``navigator.clipboard&&navigator.clipboard.writeText(id)``
followed by an unconditional ``this.textContent='✓'``.  Two independent ways to
lie: the promise was never awaited, and outside a secure context
``navigator.clipboard`` is undefined so the short-circuit copied nothing while
the button still reported success.  An error reference that silently fails to
copy is worse than no button: the operator pastes stale clipboard content into
a support request.

2026-08-30 — second round, from a real report ("el botón de copy tampoco
sirve") that could not be reproduced.  The page, its CSP nonce and both copy
paths were verified byte-for-byte in a real Chromium (secure origin, plain-http
origin, and clipboard permission denied): all three copied.  What the code
could not do was *tell anyone why* when it failed on a browser we do not have:

* the rejection handler called ``legacyCopy()``, but ``document.execCommand``
  needs the click's transient activation and a promise continuation has already
  lost it — so the fallback could only ever report a second failure;
* a promise that never settles left the button silent for good;
* the failure state was a ✗ that erased itself after two seconds, which from
  the operator's seat is indistinguishable from a button that does nothing.

These guards fix the properties, not the glyphs.
"""
import io
import os
import re

import pytest

from conftest import admin_user_id, login

TEMPLATE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    'app', 'templates', 'errors', '500.html',
)


def _html():
    return io.open(TEMPLATE, encoding='utf-8').read()


def _script_body():
    """Return the page's inline script with comments stripped.

    Comments are removed on purpose: several of the strings these guards forbid
    are legitimately named in the code's own explanatory comments, and an
    assertion that matches its own comment proves nothing.
    """
    m = re.search(r'<script[^>]*>(.*?)</script>', _html(), re.S)
    assert m, '500.html no longer has an inline script'
    body = m.group(1)
    body = re.sub(r'/\*.*?\*/', '', body, flags=re.S)
    body = re.sub(r'(?m)^\s*//.*$', '', body)
    return body


def _block_from(body, index):
    """The balanced {...} block starting at the first brace at/after ``index``."""
    start = body.index('{', index)
    depth = 0
    for k in range(start, len(body)):
        if body[k] == '{':
            depth += 1
        elif body[k] == '}':
            depth -= 1
            if depth == 0:
                return body[start:k + 1]
    raise AssertionError('unbalanced braces in the 500 page script')


def _block_after(body, marker):
    return _block_from(body, body.index(marker))


def _then_callbacks():
    """(fulfilment, rejection) bodies of writeText().then(...)."""
    body = _script_body()
    i = body.index('navigator.clipboard.writeText')
    j = body.index('.then(', i)
    first = _block_from(body, j)
    after = body.index(first, j) + len(first)
    second = _block_from(body, body.index('function', after))
    return first, second


def _click_handler():
    body = _script_body()
    return _block_after(body, "btn.addEventListener('click'")


# ---------------------------------------------------------------- round 1 --
def test_template_exists():
    assert os.path.isfile(TEMPLATE)


def test_no_unawaited_short_circuit_write():
    body = _script_body()
    assert 'navigator.clipboard&&navigator.clipboard.writeText' not in body
    # The short-circuit is fine as a feature *test* inside an if(); what is
    # forbidden is using it as the copy statement itself, because then the
    # falsy branch does nothing at all and execution falls straight through
    # to whatever reports the outcome.
    for line in body.splitlines():
        stripped = line.strip()
        if stripped.startswith('navigator.clipboard') and '&&' in stripped:
            raise AssertionError(
                'clipboard feature test used as a bare statement: %r' % stripped
            )


def test_clipboard_write_result_is_handled():
    """writeText() must have both a success and a failure continuation."""
    fulfil, reject = _then_callbacks()
    assert fulfil and reject
    body = _script_body()
    head = body[body.index('.then('):body.index(reject)]
    assert re.search(r'function\s*\(\s*e\w*\s*\)', body[body.index(reject) - 40:
                                                        body.index(reject)]), (
        'the rejection handler takes no argument, so the reason a denied or '
        'stalled clipboard gave can never reach the operator'
    )
    assert 'function' in head


def test_has_non_secure_context_fallback():
    """A plain-http hit must still have a copy path, not just a lie."""
    body = _script_body()
    assert "document.execCommand('copy')" in body or 'document.execCommand("copy")' in body
    assert 'createElement' in body


def test_success_glyph_is_never_set_unconditionally():
    """The check mark may only be written inside the success branch."""
    body = _script_body()
    assert body.count("'✓'") == 1, (
        'the success glyph is written in more than one place: one of them will '
        'eventually run without a successful copy behind it'
    )
    ok_branch = _block_after(body, 'if (ok) {')
    assert "'✓'" in ok_branch, (
        'the success glyph is assigned outside the branch that proved the copy '
        'succeeded'
    )


# ---------------------------------------------------------------- round 2 --
def test_the_rejection_branch_never_calls_the_legacy_copier():
    """execCommand cannot work from a promise callback — the gesture is gone.

    Calling it there is worse than not calling it: it turns "we could not copy,
    here is why" into "we could not copy" with the reason overwritten by a
    second, guaranteed failure.
    """
    _, reject = _then_callbacks()
    assert 'legacyCopy' not in reject, (
        'the rejection handler calls legacyCopy(); document.execCommand needs '
        "the click's transient activation, which this continuation no longer has"
    )


def test_the_legacy_path_runs_inside_the_click():
    """The synchronous path must stay where the user activation still is."""
    handler = _click_handler()
    fulfil, reject = _then_callbacks()
    assert 'legacyCopy(' in handler
    for callback in (fulfil, reject):
        assert 'legacyCopy(' not in callback
    # …and there is exactly one call site, so the property above cannot be
    # satisfied by a second copy hidden somewhere else.
    body = _script_body()
    assert len(re.findall(r'\blegacyCopy\(', body)) == 2, (
        'expected one definition and one call site of legacyCopy'
    )


def test_the_async_path_cannot_stay_silent():
    """A promise that never settles must still produce an answer."""
    handler = _click_handler()
    assert 'setTimeout' in handler, (
        'writeText() is awaited with no deadline: a permission prompt that '
        'never appears leaves the button silent for good'
    )
    guard = _block_from(handler, handler.index('setTimeout'))
    assert 'done(false' in guard, (
        'the deadline fires but reports nothing'
    )
    fulfil, reject = _then_callbacks()
    for callback in (fulfil, reject):
        assert 'clearTimeout' in callback, (
            'a settled promise does not cancel the deadline, so the outcome '
            'can be overwritten by a late timeout'
        )
        assert 'settled' in callback, (
            'nothing stops the deadline and the settlement from both reporting'
        )


def test_a_failure_state_is_not_erased_by_a_timer():
    """The old ✗ vanished after 2s, taking the diagnosis with it."""
    body = _script_body()
    done = _block_after(body, 'function done(')
    ok_branch = _block_after(done, 'if (ok) {')
    rest = done.replace(ok_branch, '')
    assert 'setTimeout' not in rest, (
        'the failure state schedules its own removal — after it clears, the '
        'page is indistinguishable from one where the button did nothing'
    )
    assert 'setTimeout' in ok_branch, (
        'the success glyph is never restored to the label, so a second attempt '
        'has no affordance'
    )


def test_the_failure_names_the_reason():
    _, reject = _then_callbacks()
    assert 'e.name' in reject, (
        'the rejection reason is discarded; the next report can only repeat '
        '"it does not work"'
    )
    body = _script_body()
    done = _block_after(body, 'function done(')
    assert 'why' in done.split('if (ok) {')[0] or 'why' in done, (
        'the reason never reaches the page'
    )
    assert re.search(r'note\.textContent\s*=.*why', done), (
        'the reason is accepted but not rendered'
    )


def test_the_failure_leaves_the_reference_selected():
    body = _script_body()
    done = _block_after(body, 'function done(')
    ok_branch = _block_after(done, 'if (ok) {')
    rest = done.replace(ok_branch, '')
    assert 'selectRef()' in rest, (
        'a failed copy leaves the operator with no way to get the reference'
    )
    assert 'note.hidden = false' in rest, 'the explanation is never shown'
    assert 'note.hidden = true' in ok_branch, (
        'a stale failure note survives a later success'
    )


def test_the_reference_is_click_to_select():
    """A path that depends on no clipboard API at all."""
    body = _script_body()
    assert re.search(r"ref\.addEventListener\('click',\s*selectRef\)", body), (
        'the reference itself cannot be selected by clicking it, so every path '
        'to the value goes through a clipboard API that may be unavailable'
    )


def test_the_manual_instruction_is_translated_server_side():
    html = _html()
    assert re.search(r'data-msg="\{\{ _\(', html), (
        "the fallback instruction is not passed through the app's translator"
    )
    body = _script_body()
    assert 'note.dataset.msg' in body, (
        'the script hardcodes the instruction instead of reading the '
        'server-rendered translation'
    )


def test_the_note_starts_hidden_and_the_button_is_still_there():
    html = _html()
    assert re.search(r'id="fw-err-note"[^>]*\shidden', html), (
        'the failure note is rendered visible on a page where nothing failed yet'
    )
    assert 'data-js="copy-err"' in html
    assert 'id="fw-err-id"' in html


# ------------------------------------------------------------- rendered ----
def test_the_rendered_script_carries_the_nonce_the_response_enforces(app, client):
    """End to end: a CSP-blocked script is a button that does nothing.

    This is the one property no amount of reading the template can settle —
    the nonce in the page has to equal the nonce in the header the *same*
    response sent, and a `csp_nonce()` call (a str is not callable) would
    render an empty attribute that blocks the whole script.
    """
    app.config['PROPAGATE_EXCEPTIONS'] = False
    login(client, admin_user_id(app))
    r = client.get('/__selftest/error')
    assert r.status_code == 500
    body = r.get_data(as_text=True)
    assert 'data-js="copy-err"' in body, 'the themed page did not render'
    header = set(re.findall(r"nonce-([A-Za-z0-9_\-]+)",
                            r.headers.get('Content-Security-Policy', '')))
    tags = re.findall(r'<(?:script|style)\s+nonce="([^"]*)"', body)
    assert tags, 'the inline blocks carry no nonce'
    assert header, 'the response enforces no nonce'
    for value in tags:
        assert value in header, (
            'an inline block carries a nonce the response does not enforce: '
            'the browser refuses it and the button silently does nothing'
        )
