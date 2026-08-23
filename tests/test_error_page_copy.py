"""Guard: the 500 page's Copy button must never claim success it did not have.

The original handler was ``navigator.clipboard&&navigator.clipboard.writeText(id)``
followed by an unconditional ``this.textContent='✓'``.  Two independent ways to
lie: the promise was never awaited, and outside a secure context
``navigator.clipboard`` is undefined so the short-circuit copied nothing while
the button still reported success.  An error reference that silently fails to
copy is worse than no button: the operator pastes stale clipboard content into
a support request.
"""
import io
import os
import re

import pytest

TEMPLATE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    'app', 'templates', 'errors', '500.html',
)


def _script_body():
    """Return the page's inline script with comments stripped.

    Comments are removed on purpose: several of the strings this guard forbids
    are legitimately named in the code's own explanatory comments, and an
    assertion that matches its own comment proves nothing.
    """
    html = io.open(TEMPLATE, encoding='utf-8').read()
    m = re.search(r'<script[^>]*>(.*?)</script>', html, re.S)
    assert m, '500.html no longer has an inline script'
    body = m.group(1)
    body = re.sub(r'/\*.*?\*/', '', body, flags=re.S)
    body = re.sub(r'(?m)^\s*//.*$', '', body)
    return body


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
    body = _script_body()
    m = re.search(r'navigator\.clipboard\.writeText\([^)]*\)\s*\.\s*then\s*\(', body)
    assert m, 'writeText() result is not handled with .then(...)'
    tail = body[m.end():m.end() + 400]
    assert re.search(r'function\s*\(\s*\)\s*\{[^}]*\}\s*,\s*function', tail), (
        'writeText().then() has no rejection handler — a denied clipboard '
        'permission would be reported as success'
    )


def test_has_non_secure_context_fallback():
    """A plain-http hit must still have a copy path, not just a lie."""
    body = _script_body()
    assert "document.execCommand('copy')" in body or 'document.execCommand("copy")' in body
    assert 'createElement' in body


def test_success_glyph_is_never_set_unconditionally():
    """No statement may set the check mark outside the flash() helper."""
    body = _script_body()
    setters = re.findall(r'textContent\s*=\s*[^;]+', body)
    assert setters, 'no textContent assignment found — did the button change?'
    for setter in setters:
        bare_success = re.match(r"textContent\s*=\s*['\"]✓['\"]\s*$", setter.strip())
        assert not bare_success, (
            'the success glyph is assigned unconditionally: %r' % setter
        )


def test_failure_is_visibly_distinct_from_success():
    body = _script_body()
    assert '✓' in body, 'no success indicator'
    assert '✗' in body, 'failure is not visually distinguishable from success'


def test_label_is_restored_after_feedback():
    body = _script_body()
    assert 'setTimeout' in body and 'label' in body, (
        'the button never returns to its original label, so a second copy '
        'attempt has no affordance'
    )
