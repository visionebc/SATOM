"""The two halves of the peer write channel were built independently.

`node_security.peer_post` (the transport) and `metrics_collect.peer_write`
(its first caller) were implemented in parallel by different hands, and the
only thing that verified they fit was somebody reading both. That is not a
guard -- it is a coincidence with a good outcome.

A signature drift here does not crash: the caller catches `TypeError` and
reports `unavailable`, which is honest but indistinguishable from "this node
has not been updated yet". So the pair could silently stop mirroring while the
page reports a state that has a perfectly reasonable explanation.
"""
from __future__ import annotations

import inspect

import pytest


def test_peer_post_exists_and_takes_host_first():
    """`peer_get(host, path, ...)` is the established shape. A write twin that
    reversed it would be a trap for every future caller."""
    from app.services import node_security as nsec
    assert hasattr(nsec, "peer_post"), "the authenticated POST channel is gone"
    params = list(inspect.signature(nsec.peer_post).parameters)
    assert params[:3] == ["host", "path", "data"], params


def test_peer_get_and_peer_post_agree_on_their_shared_parameters():
    """One transport, one convention. Two shapes is how a caller ends up
    passing a path where a host is expected and getting a plausible error."""
    from app.services import node_security as nsec
    g = list(inspect.signature(nsec.peer_get).parameters)
    p = list(inspect.signature(nsec.peer_post).parameters)
    assert g[:2] == p[:2] == ["host", "path"], (g, p)
    assert "timeout" in g and "timeout" in p


def test_the_collector_calls_the_transport_the_way_it_is_declared():
    """Bind the collector's actual call against the real signature.

    inspect.Signature.bind raises exactly where a live call would, so this
    fails for the same reason production would -- without opening a socket.
    """
    from app.services import node_security as nsec
    from app.services import metrics_collect as mc
    sig = inspect.signature(nsec.peer_post)
    sig.bind("192.0.2.2", mc.PEER_INGEST_PATH, b"x=1", timeout=mc.PEER_TIMEOUT)


def test_the_receiving_endpoint_is_the_path_the_collector_posts_to():
    """A sender and a receiver that disagree on the URL fail as 404 -- which
    the collector records as a rejected write, i.e. as the peer's fault."""
    from app import create_app
    from app.services import metrics_collect as mc
    app = create_app()
    rules = {str(r) for r in app.url_map.iter_rules()}
    assert any(mc.PEER_INGEST_PATH == r for r in rules), (
        "collector posts to %s but no route serves it" % mc.PEER_INGEST_PATH)


def test_a_missing_transport_is_its_own_state_not_unreachable():
    """Counterweight. 'this node lacks the code' and 'the other node did not
    answer' need opposite fixes: deploy here, or go look at the other box."""
    from app.services import metrics_collect as mc
    assert mc.PEER_UNAVAILABLE != mc.PEER_UNREACHABLE
    assert mc.PEER_UNCONFIGURED not in (mc.PEER_UNAVAILABLE, mc.PEER_UNREACHABLE)
