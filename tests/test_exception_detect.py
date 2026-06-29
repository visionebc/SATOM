"""Detect live per-signature exceptions off a box and bind each to its Server
Policy. A per-signature exception is a row of the signature SET's ``filter_list``;
the set is SHARED (a WPP ``signature-rule``, bound to policies), so the walk is
server policy → WPP → signature set → filter_list, attributing each row to the
policy. Pure walk over a duck-typed reader → fully testable without a device.
"""
from __future__ import annotations


class FakeReader:
    """Duck-typed reader: get_object(coll, mkey) + get_rows(sub_coll, parent)."""

    def __init__(self, objects, rows):
        self.objects = objects
        self.rows = rows
        self.set_reads = []

    def get_object(self, coll, mkey):
        return self.objects.get((coll, mkey), {})

    def get_rows(self, sub_coll, parent):
        self.set_reads.append((sub_coll, parent))
        return self.rows.get((sub_coll, parent), [])


WPP = "waf/web-protection-profile.inline-protection"
FILTER = "waf/signature/filter_list"


def test_detect_walks_policy_to_filterlist_and_cleans_noise():
    from app.services import exception_detect as det
    reader = FakeReader(
        objects={(WPP, "wpp-ecom"): {"signature-rule": "sig-set-ecom"}},
        rows={(FILTER, "sig-set-ecom"): [
            {"id": 1, "signature_id": "010000001", "match-target": "URI",
             "operator": "REGEXP_MATCH", "q_ref": 3, "can_view": 1},
        ]},
    )
    found = det.detect_signature_exceptions(reader, {"pol-ecom": "wpp-ecom"})
    assert len(found) == 1
    f = found[0]
    assert f["policy"] == "pol-ecom"
    assert f["signature_set"] == "sig-set-ecom"
    assert f["signature_id"] == "010000001"
    assert f["payload"]["match-target"] == "URI"
    assert "q_ref" not in f["payload"] and "can_view" not in f["payload"]


def test_detect_skips_wpp_without_signature_set():
    from app.services import exception_detect as det
    reader = FakeReader(objects={(WPP, "wpp-x"): {"signature-rule": ""}}, rows={})
    assert det.detect_signature_exceptions(reader, {"pol": "wpp-x"}) == []


def test_detect_reads_a_shared_set_once_and_attributes_to_each_policy():
    from app.services import exception_detect as det
    reader = FakeReader(
        objects={(WPP, "wpp-x"): {"signature-rule": "sig-shared"}},
        rows={(FILTER, "sig-shared"): [{"id": 1, "signature_id": "9"}]},
    )
    found = det.detect_signature_exceptions(reader, {"pol-a": "wpp-x", "pol-b": "wpp-x"})
    assert {f["policy"] for f in found} == {"pol-a", "pol-b"}
    # the shared set is read only ONCE even though two policies bind it
    assert reader.set_reads.count((FILTER, "sig-shared")) == 1


def test_import_detected_writes_signature_carveouts_and_dedups():
    from app.services import exception_detect as det
    calls = []

    def add(**kw):
        calls.append(kw)

    detected = [{"policy": "pol-a", "wpp": "wpp-x", "signature_set": "s",
                 "signature_id": "1", "payload": {"match-target": "URI"}}]
    n = det.import_detected_signature_exceptions(detected, add=add)
    assert n == 1
    assert calls[0]["exc_type"] == "signature_filter_item"
    assert calls[0]["category"] == "signature"
    assert calls[0]["policies"] == ["pol-a"]
    assert calls[0]["wpp_mkey"] == "wpp-x"

    # same content again → skipped (idempotent)
    n2 = det.import_detected_signature_exceptions(
        detected, add=add, existing_keys=[det.content_key(detected[0])])
    assert n2 == 0
    assert len(calls) == 1
