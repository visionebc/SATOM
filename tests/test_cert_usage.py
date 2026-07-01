# tests/test_cert_usage.py
from app.services import cert_manager as cm


class _Resp:
    def __init__(self, body): self._b = body; self.status_code = 200
    def json(self): return self._b


class _Client:
    """Minimal fake: maps an endpoint path to a canned results body."""
    def __init__(self, by_ep): self.by_ep = by_ep
    def api_call(self, method, path, *a, **k):
        for ep, body in self.by_ep.items():
            if ep in path:
                return _Resp({"results": body})
        return _Resp({"results": []})


class _Appliance:
    id = 1
    name = "f4"
    host = "fw4.example.com"
    def __init__(self, client): self._c = client
    def build_client(self, *a, **k): return self._c


def test_cert_usage_finds_all_three_binders():
    client = _Client({
        "cmdb/server-policy/policy": [
            {"name": "pol-a", "certificate": "shop-cert", "vip": ""},
            {"name": "pol-b", "certificate": "other"},
        ],
        "cmdb/system/certificate.sni": [
            {"name": "sni-1", "members": [
                {"id": "1", "local-cert": "shop-cert", "domain": "shop.example.com"},
                {"id": "2", "local-cert": "nope"}]},
        ],
        "cmdb/system/global": {"https-certificate": "shop-cert"},
    })
    a = _Appliance(client)
    usage = cm.cert_usage(a, "shop-cert")
    kinds = sorted(u["kind"] for u in usage)
    assert kinds == ["gui", "server-policy", "sni"]
    sp = next(u for u in usage if u["kind"] == "server-policy")
    assert sp["target"] == "pol-a" and sp["field"] == "certificate"
    sni = next(u for u in usage if u["kind"] == "sni")
    assert sni["target"] == "sni-1" and sni["sub_mkey"] == "1"
    gui = next(u for u in usage if u["kind"] == "gui")
    assert gui["field"] == "https-certificate"


def test_cert_usage_none_when_unbound():
    client = _Client({"cmdb/system/global": {"https-certificate": "x"}})
    assert cm.cert_usage(_Appliance(client), "shop-cert") == []


class _RecordingOps:
    def __init__(self): self.calls = []
    def update(self, endpoint, mkey, data, *, dry_run=True, sub_mkey=None):
        self.calls.append(("update", endpoint, mkey, data, dry_run, sub_mkey))
        return {"ok": True, "error": "", "request": {"path": endpoint}}


def test_swap_helpers_route_to_ops(monkeypatch):
    ops = _RecordingOps()
    monkeypatch.setattr(cm, "FortiWebOps", lambda appliance: ops)
    a = _Appliance(None)

    cm.swap_server_policy_cert(a, "pol-a", "certificate", "new-cert", dry_run=False)
    cm.swap_sni_member(a, "sni-1", "9", "new-cert", dry_run=False)
    cm.swap_gui_cert(a, "new-cert", dry_run=False)

    assert ops.calls[0] == ("update", cm.SERVER_POLICY_EP, "pol-a",
                            {"certificate": "new-cert"}, False, None)
    assert ops.calls[1] == ("update", cm.SNI_EP + "/members", "sni-1",
                            {"local-cert": "new-cert"}, False, "9")
    assert ops.calls[2] == ("update", cm.GLOBAL_EP, None,
                            {"https-certificate": "new-cert"}, False, None)
