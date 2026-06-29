"""FortiWeb wraps cmdb responses in ``{"results": …}`` AND signals logical
errors with an ``errcode`` in that envelope — frequently with HTTP 200 (and, as
seen live on fw2, sometimes HTTP 500). Two correctness rules the whole app
depends on:

* a READ of a missing object (``{"results":{"errcode":-3,"message":…}}``) must
  resolve to *empty*, not be mistaken for a found object;
* a WRITE is successful only when the body ``errcode`` is 0/absent, not merely
  because the HTTP status was < 400.
"""
from __future__ import annotations


class _Resp:
    def __init__(self, status, body):
        self.status_code = status
        self._body = body

    def json(self):
        return self._body


# ── reads: error envelope resolves to empty (Bug A) ────────────────────────
def test_results_one_treats_error_envelope_as_empty():
    from app.clients.fortiweb import FortiWebClient as C
    assert C._results_one({"results": {"errcode": -3, "message": "not found"}}) == {}
    assert C._results_one({"results": {"errcode": -651, "message": "bad"}}) == {}


def test_results_one_keeps_a_real_object():
    from app.clients.fortiweb import FortiWebClient as C
    assert C._results_one({"results": {"name": "x", "foo": 1}}) == {"name": "x", "foo": 1}
    # a success envelope with errcode 0 is data, not an error
    assert C._results_one({"results": {"errcode": 0, "name": "x"}}) == {"errcode": 0, "name": "x"}


def test_results_list_treats_error_envelope_as_empty():
    from app.clients.fortiweb import FortiWebClient as C
    assert C._results_list({"results": {"errcode": -3, "message": "not found"}}) == []
    assert C._results_list({"results": []}) == []
    assert C._results_list({"results": [{"id": 1}]}) == [{"id": 1}]


# ── writes: errcode-aware success (Bug B) ──────────────────────────────────
def test_response_ok_success_bodies():
    from app.services.fortiweb_ops import FortiWebOps as Ops
    assert Ops._response_ok(_Resp(200, {"results": {"status": "success"}})) == (True, "")
    assert Ops._response_ok(_Resp(200, {"results": {"name": "x"}})) == (True, "")


def test_response_ok_errcode_in_body_is_failure():
    from app.services.fortiweb_ops import FortiWebOps as Ops
    ok, err = Ops._response_ok(_Resp(200, {"results": {"errcode": -651, "message": "invalid value"}}))
    assert ok is False
    assert "-651" in err and "invalid value" in err


def test_response_ok_http_error_is_failure():
    from app.services.fortiweb_ops import FortiWebOps as Ops
    ok, err = Ops._response_ok(_Resp(500, {"results": {"errcode": -3, "message": "not found"}}))
    assert ok is False and "500" in err


def test_response_ok_none_response():
    from app.services.fortiweb_ops import FortiWebOps as Ops
    ok, err = Ops._response_ok(None)
    assert ok is False
