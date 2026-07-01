# tests/test_fortiweb_ops_submkey.py
from app.services.fortiweb_ops import _path


def test_path_plain():
    assert _path("cmdb/system/global", None) == "cmdb/system/global"


def test_path_mkey():
    assert _path("a/b", "pol1") == "a/b?mkey=pol1"


def test_path_sub_mkey():
    # by-parent sub-table row: ?mkey=<parent>&sub_mkey=<row id>
    assert _path("cmdb/system/certificate.sni/members", "sni1", "7") ==         "cmdb/system/certificate.sni/members?mkey=sni1&sub_mkey=7"


def test_path_sub_mkey_requires_parent():
    # sub_mkey without a parent mkey is meaningless -> ignored
    assert _path("a/b", None, "7") == "a/b"
