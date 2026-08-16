"""Guards for the three-leg transaction tracer (round 4).

The defect class this suite is shaped around is a claim SATOM cannot support:

* **Leg B is derived, not measured.** SATOM is not in the path between the
  appliance and the backend. Every guard about leg B is about it saying so, and
  about a field this firmware does not carry being reported as NOT READ rather
  than as "disabled" — the two are indistinguishable in a table and are
  opposite facts.
* **A row must not assert a behaviour from an enum.** ``http-reuse: never``
  once rendered as "connections are reused". That regression is guarded from
  the value side, not from the sentence side.
* **The server issues these requests.** Method policy, destination policy and
  the audit trail are guarded, including the refusals.
"""
from __future__ import annotations

import json
import os
import re

import pytest

from app.services import net_guard as ng
from app.services import txn_trace as tt
from tests.conftest import admin_user_id, login, make_user

SVC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "app", "services", "txn_trace.py")
JS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                  "app", "static", "js", "txn_trace.js")


def leg(status=200, headers=None, body=b"x", ok=True, error="", host="h",
        ip="192.0.2.1", port=443, scheme="https", method="GET", path="/",
        name=tt.LEG_A, timing=None, location=""):
    import hashlib
    return {
        "leg": name, "label": "", "ok": ok, "error": error,
        "request": {"method": method, "scheme": scheme, "host": host, "ip": ip,
                    "port": port, "path": path, "headers": [], "body_bytes": 0},
        "status": status, "reason": "OK", "http_version": "HTTP/1.1",
        "headers": list(headers or []), "set_cookie": [], "location": location,
        "body_bytes": len(body), "body_sha256": hashlib.sha256(body).hexdigest(),
        "body_preview": "", "truncated": False, "tls": None,
        "timing": timing or {"tcp_ms": 1, "tls_ms": 2, "ttfb_ms": 3,
                             "total_ms": 6},
    }


# --------------------------------------------------------------------------- #
#  Host header — the $host vs $http_host trap                                  #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("host,port,scheme,expect", [
    ("h.example", 443, "https", "h.example"),
    ("h.example", 80, "http", "h.example"),
    ("h.example", 64321, "https", "h.example:64321"),
    ("h.example", 8080, "http", "h.example:8080"),
    ("::1", 8443, "https", "[::1]:8443"),
])
def test_host_header_carries_a_non_default_port(host, port, scheme, expect):
    """An nginx passing ``$host`` instead of ``$http_host`` drops the port, and
    every POST behind a non-standard port then fails its CSRF referer check.
    A tracer that also drops it cannot show that."""
    assert tt._host_header(host, port, scheme) == expect


# --------------------------------------------------------------------------- #
#  Diff                                                                        #
# --------------------------------------------------------------------------- #
def test_different_status_means_the_appliance_decided():
    d = tt.diff(leg(status=403), leg(status=200, name=tt.LEG_C))
    assert d["verdict"]["key"] == "appliance_decides"
    assert "attack log" in d["verdict"]["text"]


def test_same_everything_means_the_appliance_is_not_the_problem():
    d = tt.diff(leg(), leg(name=tt.LEG_C))
    assert d["verdict"]["key"] == "transparent"


def test_header_only_difference_means_transformation():
    d = tt.diff(leg(headers=[["Strict-Transport-Security", "max-age=1"]]),
                leg(name=tt.LEG_C))
    assert d["verdict"]["key"] == "appliance_transforms"
    assert d["headers"]["added_by_appliance"][0]["header"] == \
        "strict-transport-security"


def test_body_difference_outranks_header_difference():
    d = tt.diff(leg(body=b"a", headers=[["X-Y", "1"]]),
                leg(body=b"b", name=tt.LEG_C))
    assert d["verdict"]["key"] == "body_differs"


def test_volatile_headers_are_separated_not_dropped():
    """Excluding them silently makes Content-Length invisible, and a length
    that differs while the body hash matches is a real finding."""
    d = tt.diff(leg(headers=[["Date", "a"], ["Content-Length", "1"]]),
                leg(headers=[["Date", "b"], ["Content-Length", "2"]],
                    name=tt.LEG_C))
    names = [x["header"] for x in d["headers"]["volatile"]]
    assert "date" in names and "content-length" in names
    assert d["verdict"]["key"] == "transparent"     # volatile ≠ transformation


def test_a_failed_leg_makes_the_diff_incomparable_and_says_why():
    """An empty comparison renders exactly like 'no differences found'."""
    d = tt.diff(leg(), leg(ok=False, error="TCP connect failed", name=tt.LEG_C))
    assert d["comparable"] is False
    assert "TCP connect failed" in d["why"]


def test_header_comparison_is_case_insensitive():
    d = tt.diff(leg(headers=[["Server", "nginx"]]),
                leg(headers=[["server", "nginx"]], name=tt.LEG_C))
    assert not d["headers"]["changed"] and not d["headers"]["added_by_appliance"]


def test_redirect_location_is_compared():
    d = tt.diff(leg(status=302, location="https://a/"),
                leg(status=302, location="https://b/", name=tt.LEG_C))
    assert d["redirect"]["same"] is False


# --------------------------------------------------------------------------- #
#  Leg B — derived, and honest about it                                        #
# --------------------------------------------------------------------------- #
def test_leg_b_is_flagged_as_not_measured():
    d = tt.derive_forwarded({"policy": {"status": "enable"}})
    assert d["measured"] is False
    assert "DERIVED" in d["note"] or "derived" in d["note"].lower()
    assert "cannot observe" in d["note"]


def test_a_field_this_firmware_lacks_is_absent_not_off():
    """'Disabled' and 'SATOM did not read it' look identical in a table and are
    opposite facts."""
    d = tt.derive_forwarded({"policy": {"status": "enable"}})
    fields = {a["field"] for a in d["absent"]}
    assert "monitor-mode" in fields
    assert not any(r["field"] == "monitor-mode" for r in d["rows"])
    why = next(a["why"] for a in d["absent"] if a["field"] == "monitor-mode")
    assert "not present" in why


def test_an_unread_object_is_absent_not_off():
    d = tt.derive_forwarded({"policy": {"status": "enable"}})
    pool = [a for a in d["absent"] if a["object"] == "pool"]
    assert pool and all("was not read" in a["why"] for a in pool)


@pytest.mark.parametrize("value", ["disable", "0", "off", "no", "none",
                                   "never", ""])
def test_every_fortiweb_spelling_of_off_reads_as_off(value):
    """FortiWeb spells 'off' at least six ways. The first version of this table
    read ``http-reuse: never`` as ENABLED and printed a sentence claiming
    connections were reused."""
    assert tt._state(value) in ("off", "unset")


def test_http_reuse_never_asserts_no_reuse():
    d = tt.derive_forwarded({"pool": {"http-reuse": "never"}})
    row = next(r for r in d["rows"] if r["field"] == "http-reuse")
    assert row["state"] == "off"
    assert "are reused" not in row["effect"]


def test_monitor_mode_is_called_out_loudly():
    """A request that 'got through' proves nothing while monitor mode is on,
    and that is the single most misread state on a FortiWeb."""
    d = tt.derive_forwarded({"policy": {"monitor-mode": "enable"}})
    row = next(r for r in d["rows"] if r["field"] == "monitor-mode")
    assert "NOTHING is blocked" in row["effect"]


def test_a_disabled_policy_is_called_out():
    d = tt.derive_forwarded({"policy": {"status": "disable"}})
    row = next(r for r in d["rows"] if r["field"] == "status")
    assert "DISABLED" in row["effect"]


def test_scripting_says_the_table_is_a_floor():
    """Lua can rewrite anything. A derivation table that does not admit that is
    claiming completeness it does not have."""
    d = tt.derive_forwarded({"policy": {"scripting": "enable"}})
    row = next(r for r in d["rows"] if r["field"] == "scripting")
    assert "floor" in row["effect"] or "not a complete" in row["effect"]


def test_content_routing_warns_the_legs_may_not_match():
    d = tt.derive_forwarded({"policy": {"sz_http-content-routing-list": "2"}})
    row = next(r for r in d["rows"]
               if r["field"] == "sz_http-content-routing-list")
    assert "different backend" in row["effect"]


def test_derivation_spec_has_no_duplicate_rows():
    seen = [(o, f) for o, f, _a, _on, _off in tt.DERIVATIONS]
    assert len(seen) == len(set(seen))


def test_every_derivation_names_an_object_the_deriver_knows():
    known = {"policy", "pool", "wpp", "xff", "vserver"}
    assert {o for o, *_ in tt.DERIVATIONS} <= known


def test_every_derivation_declares_where_it_applies():
    ok = {"request", "response", "routing", "tls"}
    assert {a for _o, _f, a, _on, _off in tt.DERIVATIONS} <= ok


def test_derivation_against_the_real_snapshot_resolves_every_field():
    """The field names in DERIVATIONS were read off a live FortiWeb 7.6.8
    object, not recalled. If a rename or a typo creeps in, the snapshot says
    so — and the row would otherwise vanish from the panel in silence."""
    snap = "/opt/satom/data/reports/fortiweb09/_config.json"
    if not os.path.exists(snap):
        pytest.skip("no fortiweb09 snapshot on this node")
    with open(snap) as fh:
        sec = json.load(fh)["sections"]
    pf = {
        "policy": sec["Server Policy"]["server_policy"][0],
        "pool": sec["Server Objects"]["server_pool"][0],
        "wpp": sec["Web Protection"]["webprotection_profile_inline"][0],
        "xff": sec["Application Delivery"]["x_forwarded_for"][0],
    }
    d = tt.derive_forwarded(pf)
    unknown = [a for a in d["absent"] if a["object"] in pf]
    assert not unknown, "fields not on the real object: %s" % [
        a["object"] + "." + a["field"] for a in unknown]


# --------------------------------------------------------------------------- #
#  Export                                                                      #
# --------------------------------------------------------------------------- #
def test_curl_pins_the_address_with_resolve():
    """The whole point of leg C is the SAME Host against a DIFFERENT address.
    A curl without --resolve reproduces a different request."""
    cmd = tt.to_curl(leg(host="shop.example.com", ip="192.0.2.90", port=8080,
                         scheme="http"))
    assert "--resolve shop.example.com:8080:192.0.2.90" in cmd
    assert "http://shop.example.com:8080/" in cmd


def test_curl_omits_the_default_port_from_the_url():
    cmd = tt.to_curl(leg(host="h", ip="1.2.3.4", port=443, scheme="https"))
    assert "https://h/" in cmd and "https://h:443" not in cmd


def test_curl_quotes_hostile_values():
    cmd = tt.to_curl({"request": {"method": "GET", "scheme": "https",
                                  "host": "h", "ip": "1.2.3.4", "port": 443,
                                  "path": "/;rm -rf /",
                                  "headers": [["X", "a b; whoami"]]}})
    assert "'/;rm -rf /'" in cmd or "'https://h/;rm -rf /'" in cmd
    assert "'X: a b; whoami'" in cmd


def test_har_is_valid_enough_to_load():
    har = tt.to_har([leg(), leg(name=tt.LEG_C)])
    assert har["log"]["version"] == "1.2"
    assert len(har["log"]["entries"]) == 2
    json.dumps(har)


def test_har_skips_failed_legs():
    har = tt.to_har([leg(), leg(ok=False, name=tt.LEG_C)])
    assert len(har["log"]["entries"]) == 1


def test_har_records_the_body_hash_rather_than_the_body():
    har = tt.to_har([leg(body=b"secret")])
    content = har["log"]["entries"][0]["response"]["content"]
    assert "secret" not in json.dumps(content)
    assert "sha256=" in content["comment"]


# --------------------------------------------------------------------------- #
#  Correlation is candidates, never matches                                    #
# --------------------------------------------------------------------------- #
def test_correlation_never_claims_a_match():
    import time
    now = time.time()
    res = tt.correlate([{"src": "192.0.2.1",
                         "rel_time": time.strftime("%Y-%m-%d %H:%M:%S")}],
                       now, now, src_ips=["192.0.2.1"])
    assert "candidates" in res
    assert "not matches" in res["note"].lower()
    assert res["candidates"][0]["why"]


def test_correlation_drops_entries_outside_the_window():
    import time
    now = time.time()
    res = tt.correlate([{"src": "1.2.3.4", "rel_time": "2020-01-01 00:00:00"}],
                       now, now)
    assert res["candidates"] == []


def test_source_ip_match_outranks_time_alone():
    import time
    now = time.time()
    stamp = time.strftime("%Y-%m-%d %H:%M:%S")
    res = tt.correlate([{"src": "9.9.9.9", "rel_time": stamp},
                        {"src": "192.0.2.1", "rel_time": stamp}],
                       now, now, src_ips=["192.0.2.1"])
    assert res["candidates"][0]["row"]["src"] == "192.0.2.1"


# --------------------------------------------------------------------------- #
#  Credentials never round-trip                                                #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("header", tt.REDACT)
def test_credential_headers_are_redacted(header):
    assert "s3cr3t" not in tt._redact(header, "s3cr3t")
    assert "redacted" in tt._redact(header, "s3cr3t")


def test_ordinary_headers_are_not_redacted():
    assert tt._redact("Accept", "*/*") == "*/*"


def test_set_cookie_is_reduced_to_its_flags():
    """The flags are the finding; the value is a session credential rendered
    into a browser panel."""
    c = tt._cookie_shape("SESSID=abc123; Path=/; Secure; HttpOnly; SameSite=Lax")
    assert c["name"] == "SESSID" and c["secure"] and c["httponly"]
    assert "abc123" not in json.dumps(c)


# --------------------------------------------------------------------------- #
#  Method + destination policy at the endpoint                                 #
# --------------------------------------------------------------------------- #
def test_safe_and_mutating_sets_are_disjoint():
    assert not set(tt.SAFE_METHODS) & set(tt.MUTATING_METHODS)


def test_mutating_method_needs_the_permission(app, client):
    uid = make_user(app, username="ro3", role="readonly")
    login(client, uid)
    r = client.post("/txn-trace/run",
                    json={"method": "POST", "vip": "example.com", "mode_a": "free"})
    assert r.status_code == 403
    assert ng.FREE_PERMISSION in r.get_json()["error"]


def test_mutating_method_needs_explicit_confirmation(app, client):
    """Replaying a POST 'to see what happens' is how a trace creates the ticket
    it was opened to close."""
    login(client, admin_user_id(app))
    r = client.post("/txn-trace/run",
                    json={"method": "POST", "vip": "127.0.0.1:9",
                          "mode_a": "free"})
    assert r.status_code == 409
    assert r.get_json()["needs_confirmation"] is True


def test_unknown_method_is_refused(app, client):
    login(client, admin_user_id(app))
    r = client.post("/txn-trace/run",
                    json={"method": "TRACE", "vip": "127.0.0.1:9",
                          "mode_a": "free"})
    assert r.status_code == 400


def test_free_target_needs_the_permission(app, client):
    uid = make_user(app, username="ro4", role="readonly")
    login(client, uid)
    r = client.post("/txn-trace/run",
                    json={"method": "GET", "vip": "example.com", "mode_a": "free"})
    assert r.status_code == 403


def test_metadata_destination_is_refused(app, client):
    login(client, admin_user_id(app))
    r = client.post("/txn-trace/run",
                    json={"method": "GET", "mode_a": "free",
                          "vip": "169.254.169.254:80"})
    assert r.status_code == 400
    assert "metadata" in r.get_json()["error"]


def test_a_refusal_is_audited(app, client):
    from app.models import AuditLog
    uid = make_user(app, username="ro5", role="readonly")
    login(client, uid)
    client.post("/txn-trace/run",
                json={"method": "POST", "vip": "example.com", "mode_a": "free"})
    with app.app_context():
        assert AuditLog.query.filter_by(action="txn_trace.denied").count() == 1


def test_no_target_at_all_is_refused(app, client):
    login(client, admin_user_id(app))
    r = client.post("/txn-trace/run", json={"method": "GET"})
    assert r.status_code == 400


def test_context_reports_the_method_policy(app, client):
    login(client, admin_user_id(app))
    d = client.get("/txn-trace/context").get_json()
    assert d["ok"]
    assert set(d["safe_methods"]) == set(tt.SAFE_METHODS)
    assert set(d["mutating_methods"]) == set(tt.MUTATING_METHODS)


@pytest.mark.parametrize("path", ["/txn-trace/run", "/txn-trace/derive",
                                  "/txn-trace/correlate", "/txn-trace/har"])
def test_endpoints_require_login(client, path):
    assert client.post(path, json={}).status_code in (302, 401)


def test_derive_needs_both_an_appliance_and_a_policy(app, client):
    login(client, admin_user_id(app))
    assert client.post("/txn-trace/derive",
                       json={"appliance_id": 0, "policy": ""}).status_code == 400


# --------------------------------------------------------------------------- #
#  Header sanitising                                                           #
# --------------------------------------------------------------------------- #
def test_operator_headers_cannot_inject_a_second_request(app):
    from app.views.txn_trace import _clean_headers
    out = _clean_headers({"X-A": "v\r\nX-Injected: 1", "Bad\nName": "x"})
    assert "\r" not in out["X-A"] and "\n" not in out["X-A"]
    assert "Bad\nName" not in out


def test_operator_headers_are_bounded(app):
    from app.views.txn_trace import MAX_HEADERS, _clean_headers
    out = _clean_headers({"H%d" % i: "v" for i in range(MAX_HEADERS + 20)})
    assert len(out) == MAX_HEADERS


def test_headers_accept_the_textarea_shape(app):
    from app.views.txn_trace import _clean_headers
    out = _clean_headers("X-Forwarded-For: 203.0.113.9\nAccept-Language: es-MX")
    assert out["X-Forwarded-For"] == "203.0.113.9"


# --------------------------------------------------------------------------- #
#  Panel                                                                       #
# --------------------------------------------------------------------------- #
def test_panel_says_leg_b_is_derived():
    with open(JS, encoding="utf-8") as fh:
        js = fh.read()
    assert "DERIVED, not measured" in js


def test_panel_renders_the_absent_list():
    """A setting SATOM did not read must not be invisible; invisible reads as
    'off'."""
    with open(JS, encoding="utf-8") as fh:
        js = fh.read()
    assert "d.absent" in js and 'not the same as "off"' in js


def test_panel_has_a_class_for_every_verdict():
    """Derived from the SERVICE. A verdict with no class renders neutral grey —
    which reads as 'nothing to see here' on ``appliance_decides``."""
    with open(SVC, encoding="utf-8") as fh:
        keys = set(re.findall(r'"key":\s*"([a-z_]+)"', fh.read()))
    with open(JS, encoding="utf-8") as fh:
        mapped = set(re.findall(r"(\w+):\s*'alert-", fh.read()))
    assert keys, "verdict scan anchor moved"
    assert keys <= mapped, "unmapped verdicts: %s" % (keys - mapped)


def test_panel_uses_light_theme_only():
    with open(JS, encoding="utf-8") as fh:
        js = fh.read()
    for token in ("#6ee7b7", "#fcd34d", "#fca5a5", "#93c5fd", "#c4b5fd",
                  "rgba(30,41,59", "backdrop-filter", "#080d1a"):
        assert token not in js


def test_panel_does_not_rebuild_curl_itself():
    """Two authors for one string is how the copy pasted into a ticket drifts
    from the request SATOM actually sent."""
    with open(JS, encoding="utf-8") as fh:
        js = fh.read()
    assert "r.d.curl" in js
    assert "--resolve" not in js, "the panel is composing its own curl line"
