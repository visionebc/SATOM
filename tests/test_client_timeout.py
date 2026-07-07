"""A dead/absent appliance must fail FAST.

The per-request budget stays 30 s, but the TCP/TLS *connect* leg is capped —
otherwise every request to an unplugged box burns the full budget and a long
sync (hundreds of requests) "flies" for hours instead of erroring in seconds.
"""
import httpx

from app.clients.base import BaseClient


def test_connect_timeout_is_capped():
    c = BaseClient("192.0.2.1")
    assert isinstance(c._timeout, httpx.Timeout)
    assert c._timeout.connect is not None and c._timeout.connect <= 10.0
    assert c._timeout.read == 30.0


def test_short_budget_caps_connect_too():
    c = BaseClient("192.0.2.1", timeout=5.0)
    assert c._timeout.connect <= 5.0
    assert c._timeout.read == 5.0
