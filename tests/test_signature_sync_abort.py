"""sync_signature_database must ABORT when the device dies mid-sync.

The per-sub-class reads are best-effort by design (one flaky sub-class never
kills a sync), but with the box actually GONE every remaining read fails — and
grinding through hundreds of doomed requests at full timeout each is how the
fw5 job hung for hours. N *consecutive* transport failures ⇒ device
unreachable ⇒ raise, so the job errors out in seconds.
"""
import pytest

from app.services import signature_catalog as sc


class _Resp:
    def __init__(self, payload):
        self._p = payload

    def json(self):
        return self._p


def _dict_payload(n):
    return {"results": [
        {"name": "Main%d" % i, "main_id": "%09d" % (i * 10000000),
         "sub_id": "000000000", "type": 1, "children": []}
        for i in range(1, n + 1)]}


class _DiesAfterCatalog:
    """Catalog read succeeds; every detail read fails (box unplugged)."""

    def __init__(self, subclasses=40):
        self.detail_calls = 0
        self._n = subclasses

    def api_call(self, method, path):
        if sc.SIG_DICT_PATH in path:
            return _Resp(_dict_payload(self._n))
        self.detail_calls += 1
        raise ConnectionError("box went away")


def test_aborts_after_consecutive_transport_failures():
    client = _DiesAfterCatalog(subclasses=40)
    with pytest.raises(sc.DeviceUnreachable):
        sc.sync_signature_database(client, "sig-set")
    # aborted at the threshold — did NOT grind through all 40 sub-classes
    assert client.detail_calls == sc.MAX_CONSECUTIVE_FAILURES


def test_isolated_failures_do_not_abort():
    class _Flaky:
        def __init__(self):
            self.calls = 0

        def api_call(self, method, path):
            if sc.SIG_DICT_PATH in path:
                return _Resp(_dict_payload(6))
            self.calls += 1
            if self.calls % 2:               # every other read blips
                raise ConnectionError("blip")
            return _Resp({"results": [{"id": "010000001", "desc": "x",
                                       "status": 1}]})

    db = sc.sync_signature_database(_Flaky(), "sig-set")
    assert len(db.signatures) == 3           # the successful half survived
