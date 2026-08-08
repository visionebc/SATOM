"""Every logged IP is the CLIENT's, and no client can choose which one.

SATOM is always served through a reverse proxy, so ``request.remote_addr`` is
the proxy. The audit log recorded it verbatim: on 2026-08-08 the live database
held 193 of the last 200 rows attributed to ``127.0.0.1`` — an audit trail that
cannot tell two operators apart, on a product whose whole job is authorising
changes to a WAF.

The helper that resolves this correctly (``extensions.real_client_ip``) had
existed all along and was used by exactly one caller, the rate limiter, because
that was the one place the bug was noticed. Everything else grew its own answer:
``audit.py`` and ``api_v1/auth.py`` took the peer, and ``errors.py`` parsed
``X-Forwarded-For`` itself **without checking that the peer was a trusted
proxy** — so on the one log line whose purpose is attributing a probe, the
prober picked the address.

What is guarded here is therefore not "the audit log has an IP" but the two
properties that make the IP mean anything:

* it is the **forwarded** address when the peer is a configured proxy, and
* it is **not** the forwarded address when the peer is not — otherwise any
  client can post a header and be logged as somebody else.
"""
from __future__ import annotations

import ast
import os
import re

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

#: Modules that record or log a client address. Each one is a place the bug had
#: to be fixed separately, which is the reason the source scan below exists.
IP_CALLERS = [
    "app/services/audit.py",
    "app/errors.py",
    "app/api_v1/auth.py",
    "app/auth/routes.py",
]

#: The ONE place allowed to read the peer address, because it is the place that
#: decides whether the forwarded one may be trusted instead.
RESOLVER = "app/extensions.py"


def _read(rel: str) -> str:
    with open(os.path.join(REPO, rel), encoding="utf-8") as fh:
        return fh.read()


def _code_only_py(src: str) -> str:
    """Source with comments and docstrings removed, string literals KEPT.

    Asserting on raw source lets a guard match the comment that explains it —
    this suite has done that repeatedly. ``ast.unparse`` drops comments for
    free; docstrings are removed explicitly because they survive it.
    """
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Module, ast.FunctionDef,
                                 ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        body = getattr(node, "body", None)
        if (body and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)):
            node.body = body[1:] or [ast.Pass()]
    return ast.unparse(tree)


# --------------------------------------------------------------------------- #
#  1. Behaviour — the address that lands in the row                            #
# --------------------------------------------------------------------------- #
def _log_from(app, peer: str, xff: str | None, trusted: str):
    """Write one audit row from a synthetic request and return its ip_address."""
    from app.services.audit import log_action
    from app.models import AuditLog

    os.environ["TRUSTED_PROXIES"] = trusted
    headers = {"X-Forwarded-For": xff} if xff else {}
    with app.test_request_context("/", environ_base={"REMOTE_ADDR": peer},
                                  headers=headers):
        log_action("test.ip", target="t")
    return AuditLog.query.order_by(AuditLog.id.desc()).first().ip_address


def test_the_audit_row_carries_the_client_not_the_proxy(app):
    """The defect itself: a request through the proxy was logged as the proxy."""
    with app.app_context():
        ip = _log_from(app, peer="127.0.0.1", xff="203.0.113.9",
                       trusted="127.0.0.1,::1")
    assert ip == "203.0.113.9", (
        "the audit row still records the reverse proxy, so the trail cannot "
        "distinguish two operators")


def test_a_forged_header_from_an_untrusted_peer_is_not_believed(app):
    """The half that makes the first one safe.

    Honouring ``X-Forwarded-For`` unconditionally does not fix attribution, it
    hands it to the client. A direct connection claiming to be someone else must
    be logged under the address it actually came from.
    """
    with app.app_context():
        ip = _log_from(app, peer="198.51.100.5", xff="203.0.113.9",
                       trusted="127.0.0.1")
    assert ip == "198.51.100.5", (
        "a client that sets X-Forwarded-For chose the address it is audited "
        "under — the log is now attacker-controlled")


def test_the_proxy_appended_hop_wins_over_the_one_the_client_sent(app):
    """nginx APPENDS; it does not replace. A client that pre-fills the header
    produces ``<forged>, <real>`` and only the last hop is non-forgeable."""
    with app.app_context():
        ip = _log_from(app, peer="127.0.0.1", xff="1.2.3.4, 203.0.113.9",
                       trusted="127.0.0.1")
    assert ip == "203.0.113.9"


def test_logging_outside_a_request_still_works(app):
    """Scheduled actions audit with no request at all. Attribution must degrade
    to "unknown", never to an exception — audit is best-effort by contract."""
    from app.services.audit import log_action
    from app.models import AuditLog
    with app.app_context():
        log_action("test.no_request", target="t")
        assert AuditLog.query.order_by(
            AuditLog.id.desc()).first().ip_address is None


# --------------------------------------------------------------------------- #
#  2. Source — no module may grow its own answer again                         #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("rel", IP_CALLERS)
def test_no_caller_reads_the_peer_address_directly(rel):
    """``request.remote_addr`` outside the resolver IS the bug.

    Each of these modules had its own copy of "what is the client's IP", and
    each was wrong in its own way. The rule is not "call the helper" but "there
    is one answer to this question in the tree".
    """
    assert "remote_addr" not in _code_only_py(_read(rel)), (
        f"{rel} reads the peer address itself instead of real_client_ip()")


@pytest.mark.parametrize("rel", IP_CALLERS)
def test_no_caller_parses_the_forwarded_header_itself(rel):
    """Reading the header without the trusted-peer check is strictly worse than
    reading the peer: it is wrong AND it is forgeable. ``errors.py`` did this."""
    code = _code_only_py(_read(rel))
    assert "X-Forwarded-For" not in code, (
        f"{rel} parses X-Forwarded-For itself, bypassing the trust check")


@pytest.mark.parametrize("rel", IP_CALLERS)
def test_every_caller_reaches_the_one_resolver(rel):
    assert "real_client_ip" in _code_only_py(_read(rel)), (
        f"{rel} records an address without resolving it")


def test_the_resolver_is_the_only_module_allowed_to_read_the_peer():
    """Not vacuous: the peer address must still be read SOMEWHERE, or the guards
    above would pass against a tree that had simply stopped logging IPs."""
    assert "remote_addr" in _read(RESOLVER)


def test_the_resolver_requires_a_trusted_peer_before_believing_the_header():
    """The property the whole file rests on, asserted at its source."""
    code = _code_only_py(_read(RESOLVER))
    assert "TRUSTED_PROXIES" in code
    # The trust check and the header read must be in the same condition; a
    # resolver that reads the header first and checks later still leaks.
    assert re.search(r"if\s+xff\s+and\s+peer\s+in\s+trusted", code), (
        "the forwarded header is used without gating on the peer being trusted")


def test_the_guards_above_are_not_vacuous():
    """Every file named actually exists and was read."""
    for rel in IP_CALLERS + [RESOLVER]:
        assert len(_read(rel)) > 200, rel
