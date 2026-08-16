"""Guards for the standalone false-positive explainer (round 3).

Two classes of defect this suite is built around, both silent:

1. **A field the parser drops.** The recommendation is still produced, still
   plausible, and narrower than the operator believes — the exception then
   "does nothing" and nobody can say why. So the parser must REPORT what it
   could not place, and the report is guarded.
2. **A recommendation this tool computes differently from the device-backed
   panel.** Two engines agree the day they are written. Every option here is
   proved by running ``attack_carveout``'s real assembly, and there is a guard
   that the standalone answer equals the device-backed one for the same row.
"""
from __future__ import annotations

import json
import os
import re

import pytest

from app.services import attack_carveout, attack_log, fp_triage as fp
from tests.conftest import admin_user_id, login

SVC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "app", "services", "fp_triage.py")
JS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                  "app", "static", "js", "fp_triage.js")

SYSLOG = ('date=2026-08-16 time=11:20:03 log_id="20000010" msg_id=000000123456 '
          'vd="root" policy="pol-shop-cms" main_type="Signature Detection" '
          'sub_type="Cross Site Scripting" action="Alert_Deny" '
          'src=198.51.100.31 src_port=51422 http_method="post" '
          'http_url="/api/v2/tickets?draft=1" http_host="soporte.example.com" '
          'signature_id="090200001" weird_vendor_key="zzz"')

RAWREQ = ("POST /api/v2/tickets?draft=1 HTTP/1.1\n"
          "Host: soporte.example.com\n"
          "User-Agent: curl/8.5.0\n"
          "X-Forwarded-For: 198.51.100.31, 192.0.2.40\n")

JSONROW = json.dumps({"results": [{"main_type": "Access Control",
                                   "sub_type": "Allow Method",
                                   "http_method": "PATCH",
                                   "http_url": "https://api.example.com/v2/tickets/9",
                                   "src": "198.51.100.31", "policy": "pol-api"}]})


# --------------------------------------------------------------------------- #
#  Format detection                                                            #
# --------------------------------------------------------------------------- #
def test_syslog_key_value_is_read():
    p = fp.parse(SYSLOG)
    assert p["fmt"] == "key=value"
    assert p["row"]["signature_id"] == "090200001"
    assert p["row"]["http_url"] == "/api/v2/tickets?draft=1"
    assert p["row"]["main_type"] == "Signature Detection"


def test_json_envelope_is_unwrapped():
    p = fp.parse(JSONROW)
    assert p["fmt"] == "json"
    assert p["row"]["http_method"] == "PATCH"


def test_raw_http_request_is_read():
    p = fp.parse(RAWREQ)
    assert p["fmt"] == "http-request"
    assert p["row"]["http_method"] == "POST"
    assert p["row"]["http_host"] == "soporte.example.com"


def test_raw_request_takes_the_first_xff_hop():
    """The rest of the chain is the proxies. Scoping an exception to the WAF's
    own address exempts every client behind it."""
    assert fp.parse(RAWREQ)["row"]["src"] == "198.51.100.31"


def test_raw_request_invents_no_verdict():
    """A request carries what was SENT, not what the appliance concluded.
    Synthesising a main_type here would let the tool recommend a carve-out for
    a decision no device ever made."""
    row = fp.parse(RAWREQ)["row"]
    assert "main_type" not in row and "signature_id" not in row


def test_absolute_url_yields_the_host():
    """A pipeline that folds host into the URL must not cost the operator the
    field that scopes the exception to one site."""
    assert fp.parse(JSONROW)["row"]["http_host"] == "api.example.com"


def test_explicit_host_beats_the_url_derived_one():
    p = fp.parse('http_url="https://a.example/x" http_host="b.example"')
    assert p["row"]["http_host"] == "b.example"


def test_empty_input_is_an_error_not_an_empty_recommendation():
    p = fp.parse("   ")
    assert p["row"] == {} and p["error"]


def test_unrecognisable_input_is_an_error():
    assert fp.parse("the waf blocked my request, please help")["row"] == {}


# --------------------------------------------------------------------------- #
#  Aliases + provenance                                                        #
# --------------------------------------------------------------------------- #
def test_vendor_spellings_are_mapped_and_the_mapping_is_reported():
    p = fp.parse('srcip=192.0.2.1 url="/x" host="h" method="GET" sigid="1"')
    assert p["row"]["src"] == "192.0.2.1"
    assert p["row"]["http_url"] == "/x"
    assert p["mapped"]["srcip"] == "src"


def test_unrecognised_keys_are_reported_not_swallowed():
    """A field the parser could not place is evidence the recommendation did
    not see. Hiding it is how a too-narrow carve-out survives review."""
    p = fp.parse(SYSLOG)
    assert "weird_vendor_key" in p["unmapped"]
    assert "signature_id" not in p["unmapped"]


def test_absent_deciding_fields_are_reported_with_what_they_decide():
    p = fp.parse(RAWREQ)
    keys = {m[0] for m in p["missing"]}
    assert {"main_type", "signature_id", "policy"} <= keys
    assert all(len(m[1]) > 10 for m in p["missing"]), \
        "every missing field must say what it decides, or the list is noise"


def test_a_complete_entry_reports_nothing_missing():
    assert fp.parse(SYSLOG)["missing"] == []


def test_every_alias_target_is_a_real_row_key():
    """Derived from the attack-log column vocabulary, not a typed list: an alias
    pointing at a key no column has is a field silently discarded."""
    bad = {v for v in fp.ALIASES.values() if v not in fp.ROW_KEYS}
    assert not bad, "aliases target non-existent row keys: %s" % bad


def test_row_keys_come_from_the_attack_log_columns():
    assert fp.ROW_KEYS == tuple(k for k, _ in attack_log.PRIMARY_FIELDS)


# --------------------------------------------------------------------------- #
#  Triage agrees with the device-backed panel                                  #
# --------------------------------------------------------------------------- #
def test_recommendation_is_the_same_engine_as_the_device_path():
    """If this ever diverges, the standalone tool teaches an answer the panel
    that actually saves will not honour."""
    row = fp.parse(SYSLOG)["row"]
    mine = fp.triage(row)["types"]
    theirs = attack_carveout.suggest_types(row)
    assert [t["exc_type"] for t in mine] == [t["exc_type"] for t in theirs]
    for t in mine:
        rec = attack_carveout.recommend(row, t["exc_type"])
        assert t["recommended"]["picked"] == rec["picked"]
        assert t["recommended"]["preview"] == \
            attack_carveout.build(row, t["exc_type"], rec["picked"])


def test_signature_entry_recommends_a_signature_exception_scoped_to_the_url():
    t = fp.triage(fp.parse(SYSLOG)["row"])["types"][0]
    assert t["exc_type"] == "signature_filter_item"
    assert t["recommended"]["picked"] == ["http_url"]
    assert t["recommended"]["preview"]["payload"]["signature_id"] == "090200001"


def test_a_protocol_constraint_does_not_get_a_signature_exception():
    """The whole point: the module that blocked decides where the exception
    goes, and the log row does not say so in those words."""
    row = fp.parse('main_type="HTTP Protocol Constraints" '
                   'sub_type="Illegal HTTP header length" policy="p" '
                   'url="/upload" host="api.example.com" method="POST"')["row"]
    assert fp.triage(row)["types"][0]["exc_type"] == "http_constraint_exception_item"


def test_missing_signature_id_surfaces_as_an_assembly_error():
    """Proved by RUNNING the assembly, so the panel cannot show a payload the
    device would reject."""
    prev = fp.triage(fp.parse(RAWREQ)["row"])["types"][0]["recommended"]["preview"]
    assert prev.get("errors")
    assert any("signature_id" in str(e) for e in prev["errors"])


def test_every_option_carries_a_reason():
    for t in fp.triage(fp.parse(SYSLOG)["row"])["types"]:
        assert t["why"] and len(t["why"]) > 20


# --------------------------------------------------------------------------- #
#  The refusal to save is explicit                                             #
# --------------------------------------------------------------------------- #
def test_triage_never_offers_to_save():
    t = fp.triage(fp.parse(SYSLOG)["row"])
    assert t["save"]["can_save"] is False


def test_the_refusal_explains_itself_and_names_where_to_go():
    """A tool that quietly lacks a button teaches people it is broken."""
    note = fp.SAVE_NOTE
    assert "device" in note.lower() and "browser" in note.lower()
    assert "Attack Search" in fp.triage(fp.parse(SYSLOG)["row"])["save"]["where"]


def test_no_save_route_exists(app):
    """The strongest form of the rule: not a hidden button, an absent endpoint."""
    rules = [r.rule for r in app.url_map.iter_rules()
             if r.endpoint.startswith("fp_triage.")]
    assert rules, "the blueprint is not registered"
    assert not any("save" in r or "apply" in r for r in rules)


def test_the_panel_shows_the_refusal():
    with open(JS, encoding="utf-8") as fh:
        js = fh.read()
    assert "d.save.note" in js, "the panel drops the explanation of why it cannot save"


# --------------------------------------------------------------------------- #
#  Decoder                                                                     #
# --------------------------------------------------------------------------- #
def test_percent_decoding():
    layers = fp.decode_layers("%3Cscript%3Ealert(1)%3C%2Fscript%3E")
    assert layers[0]["how"] == "percent-decode"
    assert "<script>" in layers[0]["value"]


def test_base64_payload_is_decoded():
    layers = fp.decode_layers("PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==")
    assert layers and "<script>" in layers[-1]["value"]


def test_layers_are_returned_separately():
    """One fully-decoded string hides whether the appliance matched on the
    encoded or the decoded form — which is the question."""
    layers = fp.decode_layers("%3Cb%3E%26lt%3Bi%26gt%3B%3C%2Fb%3E")
    assert [l["how"] for l in layers] == ["percent-decode", "HTML entity decode"]
    assert layers[0]["value"] == "<b>&lt;i&gt;</b>"     # still encoded once
    assert layers[1]["value"] == "<b><i></b>"           # and only then readable


@pytest.mark.parametrize("value", ["090200001", "deadbeefcafebabe", "shop.example.com",
                                   "/api/v2/tickets", ""])
def test_decoder_invents_no_layer(value):
    """base64 will 'decode' almost anything into mojibake. A layer that is not
    readable text is a coincidence dressed as evidence."""
    assert fp.decode_layers(value) == []


def test_printable_mojibake_is_still_rejected():
    """The cases above are all rejected by UTF-8 decoding, not by the
    readability test — so they never reached it, and the mutation that deleted
    that test SURVIVED. This probe decodes to VALID, printable UTF-8 that is
    nonetheless not a payload: only the alphanumeric-ratio check can refuse
    it."""
    import base64
    probe = base64.b64encode("¡¢£¤¥¦§¨©ª«¬".encode()).decode().rstrip("=")
    assert probe.isalnum() or set(probe) <= set(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
    decoded = base64.b64decode(probe + "=" * (-len(probe) % 4)).decode("utf-8")
    assert decoded.isprintable(), "the probe must survive the UTF-8 gate"
    assert fp.decode_layers(probe) == []


def test_decoder_terminates_on_a_cycle():
    assert len(fp.decode_layers("%25" * 50)) <= 4


# --------------------------------------------------------------------------- #
#  Endpoints                                                                   #
# --------------------------------------------------------------------------- #
def test_triage_endpoint(app, client):
    login(client, admin_user_id(app))
    r = client.post("/fp-triage/triage", json={"text": SYSLOG})
    assert r.status_code == 200
    d = r.get_json()
    assert d["ok"] and d["types"][0]["exc_type"] == "signature_filter_item"
    assert d["save"]["can_save"] is False


def test_triage_endpoint_rejects_unreadable_input(app, client):
    login(client, admin_user_id(app))
    r = client.post("/fp-triage/triage", json={"text": "nothing useful here"})
    assert r.status_code == 400
    assert r.get_json()["error"]


def test_parse_endpoint_reports_provenance(app, client):
    login(client, admin_user_id(app))
    d = client.post("/fp-triage/parse", json={"text": SYSLOG}).get_json()
    assert "weird_vendor_key" in d["unmapped"]


def test_decode_endpoint(app, client):
    login(client, admin_user_id(app))
    d = client.post("/fp-triage/decode",
                    json={"value": "%3Cscript%3E"}).get_json()
    assert d["ok"] and d["layers"][0]["value"] == "<script>"


@pytest.mark.parametrize("path", ["/fp-triage/parse", "/fp-triage/triage",
                                  "/fp-triage/decode"])
def test_endpoints_require_login(client, path):
    assert client.post(path, json={}).status_code in (302, 401)


def test_input_is_capped(app, client):
    login(client, admin_user_id(app))
    r = client.post("/fp-triage/triage",
                    json={"text": SYSLOG + " " + "x=" + "y" * 200000})
    assert r.status_code in (200, 400)


# --------------------------------------------------------------------------- #
#  Panel chrome                                                                #
# --------------------------------------------------------------------------- #
def test_panel_uses_light_theme_only():
    with open(JS, encoding="utf-8") as fh:
        js = fh.read()
    for token in ("#6ee7b7", "#fcd34d", "#fca5a5", "#93c5fd", "#c4b5fd",
                  "rgba(30,41,59", "backdrop-filter", "#080d1a"):
        assert token not in js


def test_panel_renders_the_unused_fields():
    """The report of what was NOT used is the finding; a panel that computes it
    and does not draw it is the same as not computing it."""
    with open(JS, encoding="utf-8") as fh:
        js = fh.read()
    assert "d.unmapped" in js and "d.missing" in js


def test_service_names_the_device_backed_contract_it_defers_to():
    """This module exists because attack_carveout refuses browser-supplied
    evidence. If that sentence leaves the file, the next reader deletes the
    refusal as an oversight."""
    with open(SVC, encoding="utf-8") as fh:
        body = " ".join(fh.read().split())
    assert "never from values the browser sent back" in body \
        or "never from values a browser sent back" in body
