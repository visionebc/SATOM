"""The Configuration browser must surface a device-level REST refusal
(license lock, auth failure, dead host) instead of rendering an empty list."""
import types

from app.clients.fortiweb import FortiWebClient


class _Resp:
    def __init__(self, status_code, body):
        self.status_code = status_code
        self._body = body

    def json(self):
        if isinstance(self._body, Exception):
            raise self._body
        return self._body


def _client_with(resp=None, exc=None):
    c = FortiWebClient.__new__(FortiWebClient)  # skip __init__ (no appliance)
    if exc is not None:
        def _get(path):
            raise exc
    else:
        def _get(path):
            return resp
    c.get = _get
    return c


def test_license_lock_423_is_surfaced():
    resp = _Resp(423, {"errcode": "-20010",
                       "message": "The license of peer VM FortiWeb is not valid."})
    rows, err = _client_with(resp).list_with_error('/api/v2.0/cmdb/system/ntp/ntpserver')
    assert rows == []
    assert '-20010' in err and 'license' in err.lower()


def test_absent_endpoint_20001_stays_benign_empty():
    resp = _Resp(500, {"errcode": -20001, "message": "invalid URL"})
    rows, err = _client_with(resp).list_with_error('/api/v2.0/cmdb/waf/nonexistent')
    assert rows == [] and err is None


def test_not_found_minus3_stays_benign_empty():
    resp = _Resp(200, {"results": {"errcode": -3, "message": "entry not found"}})
    rows, err = _client_with(resp).list_with_error('/api/v2.0/cmdb/server-policy/policy')
    assert rows == [] and err is None


def test_ok_list_passes_through():
    resp = _Resp(200, {"results": [{"id": 1, "server": "pool.ntp.org"},
                                   {"id": 2, "server": "192.0.2.2"}]})
    rows, err = _client_with(resp).list_with_error('/api/v2.0/cmdb/system/ntp/ntpserver')
    assert err is None
    assert [r["server"] for r in rows] == ["pool.ntp.org", "192.0.2.2"]


def test_http_error_without_json_is_surfaced():
    resp = _Resp(502, ValueError("not json"))
    rows, err = _client_with(resp).list_with_error('/x')
    assert rows == [] and err == 'HTTP 502'


def test_transport_exception_is_surfaced():
    rows, err = _client_with(exc=ConnectionError("connect timeout")).list_with_error('/x')
    assert rows == [] and 'connect timeout' in err
