"""A deployment served over plain HTTP with ``Secure`` session cookies can
sign NOBODY in, and nothing about it looks broken while that is true.

The browser withholds a ``Secure`` cookie from a plain-HTTP origin, so the
login POST carries no session, there is no CSRF token to match, and the CSRF
handler bounces back to the login form. The container is healthy, ``/healthz``
answers 200, the login page renders, and the account is not even locked out --
the password is never compared. The one operator-visible artefact was the
flash "Your session expired or the form was stale", which is a *lie* in this
case and sends the operator off to retype a correct password forever. That is
what satom-node-1-dock did on 2026-08-31.

The hard part is not detecting plain HTTP; it is NOT firing on the healthy
deployments that also see plain HTTP. A reverse proxy that terminates TLS
speaks HTTP to the app, so ``request.scheme`` reads ``http`` on the working
production cluster too. The discriminator is ``X-Forwarded-Proto``, which the
DMZ HAProxy sets (measured, ``backend bk_satom_dock``). A guard that cried
misconfiguration at production would be worse than the bug it describes, so
that case is asserted here explicitly.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from flask_wtf.csrf import CSRFError

from app import extensions as ext
from app.extensions import client_scheme, insecure_session_transport

REPO = Path(__file__).resolve().parent.parent
STALE = "Your session expired or the form was stale"


@pytest.fixture()
def boom(app):
    """An app with a route that fails CSRF.

    The shared ``app`` fixture disables CSRF app-wide, so driving a real form
    would test the fixture, not the handler. Raising the exception the handler
    is registered for exercises the handler itself, which is what is under
    test.
    """
    @app.route("/__csrf_boom", methods=["POST"])
    def _boom():  # pragma: no cover - never returns
        raise CSRFError("The CSRF token is missing.")

    return app


def _flashes(client) -> list[str]:
    with client.session_transaction() as sess:
        return [m for _cat, m in sess.get("_flashes", [])]


# --------------------------------------------------------------- client_scheme

def test_client_scheme_prefers_the_forwarded_header(app):
    """The proxy is the only witness to what the browser actually used."""
    with app.test_request_context("/", headers={"X-Forwarded-Proto": "https"}):
        assert client_scheme() == "https"


def test_client_scheme_falls_back_to_the_request_when_unproxied(app):
    with app.test_request_context("/"):
        assert client_scheme() == "http"


def test_client_scheme_takes_the_first_hop_of_a_chain(app):
    """The client-facing hop is the first one; taking the last would report
    the scheme of the innermost proxy, which is always plain HTTP."""
    with app.test_request_context("/", headers={"X-Forwarded-Proto": "https, http"}):
        assert client_scheme() == "https"


def test_client_scheme_is_case_insensitive(app):
    with app.test_request_context("/", headers={"X-Forwarded-Proto": "HTTPS"}):
        assert client_scheme() == "https"


# ------------------------------------------------- insecure_session_transport

def test_not_insecure_when_cookies_are_not_marked_secure(app):
    """Plain HTTP is a deliberate, working configuration when the flag is off.
    Firing here would flag every development host install."""
    app.config["SESSION_COOKIE_SECURE"] = False
    with app.test_request_context("/"):
        assert insecure_session_transport() is False


def test_insecure_when_secure_cookies_meet_plain_http(app):
    app.config["SESSION_COOKIE_SECURE"] = True
    with app.test_request_context("/"):
        assert insecure_session_transport() is True


def test_not_insecure_behind_a_tls_offloading_proxy(app):
    """THE false positive that matters: the production cluster is healthy and
    is spoken to over plain HTTP. HAProxy sets X-Forwarded-Proto: https."""
    app.config["SESSION_COOKIE_SECURE"] = True
    with app.test_request_context("/", headers={"X-Forwarded-Proto": "https"}):
        assert insecure_session_transport() is False


def test_insecure_when_the_proxy_declares_plain_http(app):
    """A terminator that forwards `http` is reporting the trap, not hiding it."""
    app.config["SESSION_COOKIE_SECURE"] = True
    with app.test_request_context("/", headers={"X-Forwarded-Proto": "http"}):
        assert insecure_session_transport() is True


# ---------------------------------------------------------- the CSRF handler

def test_csrf_on_plain_http_names_the_deployment_problem(boom):
    boom.config["SESSION_COOKIE_SECURE"] = True
    client = boom.test_client()
    resp = client.post("/__csrf_boom")

    assert resp.status_code in (301, 302, 303)
    msgs = _flashes(client)
    assert msgs, "the handler flashed nothing"
    assert ext.INSECURE_TRANSPORT_HINT in msgs
    assert not any(STALE in m for m in msgs), "still blaming the user's session"


def test_csrf_behind_tls_keeps_the_ordinary_message(boom):
    """A genuine stale form on a healthy deployment must read as one."""
    boom.config["SESSION_COOKIE_SECURE"] = True
    client = boom.test_client()
    client.post("/__csrf_boom", headers={"X-Forwarded-Proto": "https"})

    msgs = _flashes(client)
    assert any(STALE in m for m in msgs)
    assert ext.INSECURE_TRANSPORT_HINT not in msgs


def test_json_caller_gets_the_deployment_problem(boom):
    boom.config["SESSION_COOKIE_SECURE"] = True
    client = boom.test_client()
    resp = client.post("/__csrf_boom", headers={"Accept": "application/json"})

    assert resp.status_code == 400
    assert resp.get_json()["error"] == ext.INSECURE_TRANSPORT_HINT


def test_json_caller_keeps_the_ordinary_message_behind_tls(boom):
    boom.config["SESSION_COOKIE_SECURE"] = True
    client = boom.test_client()
    resp = client.post(
        "/__csrf_boom",
        headers={"Accept": "application/json", "X-Forwarded-Proto": "https"},
    )

    assert resp.status_code == 400
    assert "CSRF token" in resp.get_json()["error"]
    assert resp.get_json()["error"] != ext.INSECURE_TRANSPORT_HINT


def test_the_hint_has_one_author(boom):
    """The flash, the JSON error and the log all render the same constant.
    Two authors of one sentence is how surfaces drift apart."""
    boom.config["SESSION_COOKIE_SECURE"] = True
    client = boom.test_client()
    resp = client.post("/__csrf_boom", headers={"Accept": "application/json"})
    client2 = boom.test_client()
    client2.post("/__csrf_boom")

    assert resp.get_json()["error"] in _flashes(client2)


def test_the_hint_points_somewhere_that_exists(boom):
    """A message naming a document nobody can open is a dead end."""
    assert "docs/docker.md" in ext.INSECURE_TRANSPORT_HINT
    assert (REPO / "docs" / "docker.md").is_file()


# -------------------------------------------------------------------- docs

def test_docker_doc_states_the_tls_requirement():
    """The trap cost a session precisely because no document mentioned it."""
    text = (REPO / "docs" / "docker.md").read_text()
    flat = " ".join(text.split())  # the body is hard-wrapped; anchors must not
    assert "## TLS is not optional" in text
    for needle in ("SESSION_COOKIE_SECURE", "$http_host", "X-Forwarded-Proto"):
        assert needle in flat, needle
    assert "no password works" in flat


def test_env_example_does_not_still_call_development_unproxied():
    """It used to read 'Empty in development (direct access)' — the sentence
    that authorised the broken node."""
    text = (REPO / "deploy" / "docker" / "env.example").read_text()
    flat = " ".join(text.split())
    assert "Empty in development" not in flat
    assert "127.0.0.1:8080" in flat
