"""Guards for the FortiADC Analysis page.

The defect these exist for is not a crash. ``/analysis/`` returned 200 in the
FortiADC ADOM and rendered the complete FortiWeb WAF dashboard — server
policies, web-protection profiles, App IDs, signature exceptions — every panel
at zero, because a FortiADC harvest contains none of those objects. Nothing
failed. The page simply answered a different product's questions, and an empty
panel reads as "quiet", not as "not applicable".

So the guards are about *what the page is allowed to claim*, plus the handful
of vendor quirks that would make it claim it wrongly:

* payload keys transcribed from a live FortiADC 8.0.3 object, including the
  fact that the separator is inconsistent within a single object;
* values padded with trailing spaces;
* an IPS profile whose ``mkey`` is empty;
* "not harvested" never collapsing into "zero".

Every one was verified to bite by reintroducing the behaviour it forbids.
"""
from __future__ import annotations

import pytest

from app.extensions import db
from app.models import Appliance
from app.models_cache import DeviceObject, DeviceSnapshot
from app.services import analysis_adc as A
from app.views import analysis as analysis_view
from tests.conftest import login


# --------------------------------------------------------------------------- #
#  Fixtures built from a REAL FortiADC 8.0.3 payload                           #
# --------------------------------------------------------------------------- #
#: Transcribed from ``load_balance_virtual_server`` on a live unit. The keys
#: matter more than the values: ``waf-profile`` and ``av-profile`` are
#: hyphenated while ``ips_profile``/``dos_profile``/``auth_policy``/
#: ``ztna_profile`` are not, and ``port`` carries a trailing space.
LIVE_VS = {
    "mkey": "vs-lab-demo", "pool": "pool-lab-demo", "port": "80 ",
    "type": "l4-load-balance", "status": "enable", "address": "192.0.2.199",
    "profile": "LB_PROF_TCP", "method": "LB_METHOD_ROUND_ROBIN",
    "interface": "port1", "availability": "HEALTHY", "traffic-log": "disable",
    "persistence": "", "connection-limit": "0",
    "waf-profile": "", "av-profile": "", "ips_profile": "",
    "dos_profile": "", "auth_policy": "", "ztna_profile": "",
}

LIVE_POOL = {
    "mkey": "pool-lab-demo", "type": "static", "pool_type": "ipv4",
    "service_port": "80", "availability": "HEALTHY",
    "health_check": "disable", "health_check_list": "",
    "health_check_action": "reject", "pool_member_count": 1,
}

LIVE_MEMBER = {
    "mkey": "1", "status": "enable", "address": "192.0.2.200", "port": "80",
    "weight": "1", "backup": "disable", "real_server_id": "rs-lab-demo",
}

LIVE_RS = {"mkey": "rs-lab-demo", "type": "ip", "status": "enable",
           "address": "192.0.2.200", "FQDN": ""}

#: The IPS profile object really does ship an EMPTY ``mkey``.
LIVE_IPS = {"ips_profile_name": "high_security", "_noneditable": 1,
            "comments": "Blocks all Critical/High severity signatures."}

LIVE_WAF = {
    "mkey": "Alert-Only", "desc": "", "_noneditable": 1, "_nondeletable": 1,
    "use_original_ip": "disable", "rule_match_record": "disable",
    "exception_name": "",
    "web_attack_signature": "Alert-Only", "http_protocol_constraint": "Alert-Only",
    "heuristic_sql_xss_injection_detection": "Alert-Only",
    "url_protection": "", "cookie_security": "", "csrf_protection": "",
    "bot_detection_name": "", "json_validation_name": "",
}


def _adc(app, name="adc-t1"):
    with app.app_context():
        a = Appliance(name=name, host="192.0.2.76", kind="fortiadc",
                      username="admin")
        a.password = "pw"     # setter encrypts; both columns are NOT NULL
        db.session.add(a)
        db.session.commit()
        return a.id


def _ingest(app, aid, items):
    """``items`` = ``[(logical_name, payload, parent_key_or_None)]``.

    Returns ``{mkey: DeviceObject.id}`` so members can be parented onto pools
    the way the real harvest does (depth 1, ``parent_id`` set).
    """
    ids = {}
    with app.app_context():
        snap = DeviceSnapshot(appliance_id=aid, layer="config")
        db.session.add(snap)
        db.session.flush()
        for logical, payload, parent in items:
            obj = DeviceObject(
                appliance_id=aid, snapshot_id=snap.id, layer="config",
                section="Server Load Balance", logical_name=logical,
                mkey=str(payload.get("mkey", "")), payload=payload,
                depth=1 if parent else 0,
                parent_id=ids.get(parent) if parent else None)
            db.session.add(obj)
            db.session.flush()
            ids[str(payload.get("mkey", ""))] = obj.id
        db.session.commit()
    return ids


def _appl(app, aid):
    return Appliance.query.get(aid)


# --------------------------------------------------------------------------- #
#  1. Dispatch — FortiADC no longer borrows the FortiWeb page                  #
# --------------------------------------------------------------------------- #
def test_fortiadc_does_not_get_the_fortiweb_page():
    assert analysis_view.ANALYSIS_PAGES["fortiadc"] == "analysis/adc.html"
    assert (analysis_view.ANALYSIS_PAGES["fortiadc"]
            != analysis_view.ANALYSIS_PAGES["fortiweb"])


def test_fortiadc_is_answered_by_its_own_service():
    """The template alone is not enough: pointed at ``services.analysis`` the
    ADC page would render from FortiWeb projections that are always empty."""
    assert analysis_view.ANALYSIS_SERVICE["fortiadc"] == "analysis_adc"
    assert analysis_view._analysis_service("fortiadc") is A
    from app.services import analysis as fw_ana
    assert analysis_view._analysis_service("fortiadc") is not fw_ana


def test_the_adc_page_carries_no_fortiweb_vocabulary(client, app):
    """The concrete symptom the user reported."""
    _adc(app)
    login(client, 1, product="fortiadc")
    body = client.get("/analysis/",
                      headers={"X-ADOM": "fortiadc"}).get_data(as_text=True)
    for term in ("Web Protection Profile", "web-protection-profile",
                 "Server policies", "Signature exception", "App ID"):
        assert term not in body, "FortiWeb vocabulary %r on the ADC page" % term
    assert "Analysis — delivery" in body


def test_the_adc_page_names_the_objects_an_adc_actually_has(client, app):
    aid = _adc(app)
    _ingest(app, aid, [(A._VS, LIVE_VS, None), (A._POOL, LIVE_POOL, None),
                       (A._MEMBER, LIVE_MEMBER, "pool-lab-demo")])
    login(client, 1, product="fortiadc")
    body = client.get("/analysis/",
                      headers={"X-ADOM": "fortiadc"}).get_data(as_text=True)
    for term in ("Virtual servers", "vs-lab-demo", "pool-lab-demo",
                 "Pools with no health check"):
        assert term in body


# --------------------------------------------------------------------------- #
#  2. DB-first contract                                                        #
# --------------------------------------------------------------------------- #
def test_rendering_the_adc_analysis_never_opens_a_connection(app, monkeypatch):
    """Monkeypatched to EXPLODE rather than to a stub: a stub returning empty
    would let a live call through looking like a device with no data."""
    _adc(app)

    def boom(*_a, **_k):
        raise AssertionError("analysis_adc contacted an appliance")

    import app.clients.fortiadc as adc_client
    monkeypatch.setattr(adc_client, "FortiADCClient", boom)
    with app.test_request_context("/analysis/"):
        out = A.analyze({})
    assert out["product"] == "fortiadc"


# --------------------------------------------------------------------------- #
#  3. The vendor quirks — where a wrong answer would look right                #
# --------------------------------------------------------------------------- #
def test_security_slot_keys_match_a_real_payload():
    """The highest-value guard in this file.

    FortiADC mixes separators inside one object. "Normalising" ``waf-profile``
    to ``waf_profile`` makes every lookup miss, which renders as *no security
    profile attached anywhere* — a page confidently reporting the fleet is
    unprotected. There is no exception and no crash to notice it by.
    """
    for key, _label in A._VS_SECURITY_SLOTS:
        assert key in LIVE_VS, (
            "%r is not a key on a real FortiADC virtual server; reading it "
            "would silently report 'not attached'" % key)
    # And the mix really is present — if a firmware ever normalises it, this
    # fails and the fixture must be re-transcribed from a live unit.
    fields = {k for k, _l in A._VS_SECURITY_SLOTS}
    assert any("-" in f for f in fields) and any("_" in f for f in fields)


def test_values_padded_with_trailing_spaces_are_still_read(app):
    """``"status": "enable "`` and ``"port": "80 "`` come off the wire padded.
    An unstripped compare reports an enabled service as disabled."""
    aid = _adc(app)
    padded = dict(LIVE_VS, status="enable ", port="80 ", pool="pool-lab-demo ")
    _ingest(app, aid, [(A._VS, padded, None)])
    with app.app_context():
        out = A.delivery([_appl(app, aid)])
    row = out["rows"][0]
    assert row["status"] == "enabled"
    assert row["port"] == "80"
    assert row["pool"] == "pool-lab-demo"
    assert out["enabled"] == 1


def test_ips_profile_name_comes_from_the_payload_not_the_empty_mkey(app):
    """The real object ships ``mkey: ""``; reading it renders blank rows."""
    aid = _adc(app)
    _ingest(app, aid, [(A._IPS, LIVE_IPS, None)])
    with app.app_context():
        out = A.security([_appl(app, aid)])
    assert [r["name"] for r in out["ips_profiles"]] == ["high_security"]


def test_a_pool_is_health_checked_by_either_the_flag_or_the_list(app):
    """The ADC carries both. Requiring the flag alone misses a list-driven
    setup and invents an outage warning for a correctly configured pool."""
    aid = _adc(app)
    by_list = dict(LIVE_POOL, mkey="p-list", health_check="disable",
                   health_check_list="LB_HLTHCK_HTTP")
    by_flag = dict(LIVE_POOL, mkey="p-flag", health_check="enable",
                   health_check_list="")
    neither = dict(LIVE_POOL, mkey="p-none")
    _ingest(app, aid, [(A._POOL, by_list, None), (A._POOL, by_flag, None),
                       (A._POOL, neither, None)])
    with app.app_context():
        out = A.backends([_appl(app, aid)])
    got = {r["name"]: r["health_check"] for r in out["rows"]}
    assert got == {"p-list": True, "p-flag": True, "p-none": False}
    assert out["pools_without_health_check"] == 1


def test_certificate_expiry_survives_the_timezone_abbreviation(app):
    """``validto`` ends in ``PST``/``PDT``. ``%Z`` cannot parse arbitrary
    abbreviations, so a naive parse yields None and every certificate — expired
    ones included — renders as "unparsed"."""
    from datetime import datetime, timedelta
    aid = _adc(app)
    now = datetime.utcnow()
    gone = (now - timedelta(days=5)).strftime("%Y-%m-%d %H:%M:%S") + " PST"
    soon = (now + timedelta(days=9)).strftime("%Y-%m-%d %H:%M:%S") + " PDT"
    far = (now + timedelta(days=900)).strftime("%Y-%m-%d %H:%M:%S") + " PST"
    _ingest(app, aid, [
        (A._CERT, {"mkey": "expired", "validto": gone}, None),
        (A._CERT, {"mkey": "soon", "validto": soon}, None),
        (A._CERT, {"mkey": "fine", "validto": far}, None)])
    with app.app_context():
        out = A.tls([_appl(app, aid)])
    days = {r["name"]: r["days_left"] for r in out["certificates"]}
    assert days["expired"] is not None and days["expired"] < 0
    assert 0 <= days["soon"] <= A._CERT_WARN_DAYS
    assert days["fine"] > A._CERT_WARN_DAYS
    assert out["cert_expired"] == 1 and out["cert_expiring"] == 1
    sev = {t: s for _d, s, t, _x in out["findings"]}
    assert sev["Local certificate has expired"] == "crit"
    assert sev["Local certificate expires soon"] == "warn"


def test_legacy_tls_is_flagged_and_modern_tls_is_not(app):
    aid = _adc(app)
    _ingest(app, aid, [
        (A._CSSL, {"mkey": "old", "ssl-allowed_versions": "tlsv1.0 tlsv1.1 tlsv1.2 "}, None),
        (A._CSSL, {"mkey": "new", "ssl-allowed_versions": "tlsv1.2 tlsv1.3 "}, None)])
    with app.app_context():
        out = A.tls([_appl(app, aid)])
    legacy = {r["name"]: r["legacy"] for r in out["profiles"]}
    assert legacy["old"] == ["tlsv1.0", "tlsv1.1"]
    assert legacy["new"] == []
    assert out["profiles_with_legacy"] == 1


def test_objects_are_deduplicated_by_key(app):
    """A re-sweep landing mid-page must not double every count; a count that
    doubles is a count nobody can act on."""
    aid = _adc(app)
    _ingest(app, aid, [(A._VS, LIVE_VS, None)])
    _ingest(app, aid, [(A._VS, dict(LIVE_VS, status="disable"), None)])
    with app.app_context():
        out = A.delivery([_appl(app, aid)])
    assert out["total"] == 1
    assert out["rows"][0]["status"] == "disabled", "newest row must win"


# --------------------------------------------------------------------------- #
#  4. "Not harvested" is never "zero"                                          #
# --------------------------------------------------------------------------- #
def test_an_unharvested_pool_section_produces_no_findings(app):
    """A dangling-pool or missing-health-check warning derived from a section
    the sweep never collected is a fabricated outage."""
    aid = _adc(app)
    _ingest(app, aid, [(A._VS, LIVE_VS, None)])      # virtual server only
    with app.app_context():
        out = A.backends([_appl(app, aid)])
        deliv = A.delivery([_appl(app, aid)])
    assert out["harvested"] is False
    assert out["findings"] == []
    titles = {t for _d, _s, t, _x in deliv["findings"]}
    assert "Virtual server names a missing pool" not in titles, (
        "with no pools in cache EVERY pool reference looks dangling")


def test_a_dangling_pool_reference_is_reported_once_pools_exist(app):
    """The positive half — without it the guard above is satisfied by a
    function that never reports anything at all."""
    aid = _adc(app)
    _ingest(app, aid, [(A._VS, dict(LIVE_VS, pool="ghost-pool"), None),
                       (A._POOL, LIVE_POOL, None)])
    with app.app_context():
        out = A.delivery([_appl(app, aid)])
    titles = {t for _d, _s, t, _x in out["findings"]}
    assert "Virtual server names a missing pool" in titles


def test_an_unreferenced_real_server_needs_the_member_section(app):
    """With no members in cache every real server looks orphaned."""
    aid = _adc(app)
    _ingest(app, aid, [(A._RS, LIVE_RS, None)])
    with app.app_context():
        out = A.backends([_appl(app, aid)])
    titles = {t for _d, _s, t, _x in out["findings"]}
    assert "Real server is not in any pool" not in titles

    aid2 = _adc(app, "adc-t2")
    _ingest(app, aid2, [(A._POOL, LIVE_POOL, None),
                        (A._MEMBER, dict(LIVE_MEMBER, real_server_id="other"),
                         "pool-lab-demo"),
                        (A._RS, LIVE_RS, None)])
    with app.app_context():
        out2 = A.backends([_appl(app, aid2)])
    titles2 = {t for _d, _s, t, _x in out2["findings"]}
    assert "Real server is not in any pool" in titles2


def test_not_harvested_is_distinguishable_from_zero_in_the_inventory(app):
    aid = _adc(app)
    with app.app_context():
        rows = A.inventory([_appl(app, aid)])["rows"]
    assert rows
    for row in rows:
        for per in row["devices"]:
            assert per["harvested"] is False


# --------------------------------------------------------------------------- #
#  5. Security: defined is not applied                                         #
# --------------------------------------------------------------------------- #
def test_a_bare_virtual_server_is_reported_even_when_profiles_exist(app):
    """"Profiles exist" and "profiles are applied" are different statements
    and only the second one inspects traffic."""
    aid = _adc(app)
    _ingest(app, aid, [(A._VS, LIVE_VS, None), (A._WAF, LIVE_WAF, None)])
    with app.app_context():
        sec = A.security([_appl(app, aid)])
        deliv = A.delivery([_appl(app, aid)])
    assert sec["waf_total"] == 1          # a profile IS defined
    assert sec["fully_bare"] == 1         # and nothing references it
    assert all(c["attached"] == 0 for c in sec["coverage"])
    titles = {t for _d, _s, t, _x in deliv["findings"]}
    assert "Published service has no security profile" in titles


def test_attaching_a_profile_clears_the_bare_count(app):
    aid = _adc(app)
    _ingest(app, aid, [(A._VS, dict(LIVE_VS, **{"waf-profile": "Alert-Only"}),
                        None)])
    with app.app_context():
        sec = A.security([_appl(app, aid)])
    assert sec["fully_bare"] == 0
    got = {c["slot"]: c["attached"] for c in sec["coverage"]}
    assert got["WAF"] == 1 and got["IPS"] == 0


def test_waf_module_slots_are_derived_not_listed(app):
    """A hand-written module list would silently stop counting the module the
    next firmware adds. Everything on the object that is not metadata counts."""
    aid = _adc(app)
    extended = dict(LIVE_WAF, brand_new_module_name="Alert-Only")
    _ingest(app, aid, [(A._WAF, extended, None)])
    with app.app_context():
        sec = A.security([_appl(app, aid)])
    row = sec["waf_profiles"][0]
    assert row["modules_total"] == len(
        [k for k in extended if k not in A._WAF_NON_MODULE])
    assert row["modules_filled"] == 4      # 3 shipped + the new one
    assert row["factory"] is True


def test_the_all_factory_finding_is_per_device(app):
    """Rolling several appliances into one finding attributed to whichever
    sorted first is a sentence about nobody."""
    a1 = _adc(app, "adc-x1")
    a2 = _adc(app, "adc-x2")
    for aid in (a1, a2):
        _ingest(app, aid, [(A._WAF, LIVE_WAF, None)])
    with app.app_context():
        sec = A.security([_appl(app, a1), _appl(app, a2)])
    devs = sorted(d for d, _s, t, _x in sec["findings"]
                  if t == "Every WAF profile is a factory default")
    assert devs == ["adc-x1", "adc-x2"]


# --------------------------------------------------------------------------- #
#  6. Inventory is derived, and the prefix list polices itself                 #
# --------------------------------------------------------------------------- #
def test_inventory_rows_come_from_the_registry_not_a_hand_written_list(app):
    from app.registry import loader

    aid = _adc(app)
    with app.app_context():
        rows = A.inventory([_appl(app, aid)])["rows"]
        reg = set(loader.load_adc_registry())
    got = {r["endpoint"] for r in rows}
    assert got, "inventory produced no rows at all"
    assert got == {n for n in reg if n.startswith(A._COUNTABLE_PREFIX)}


def test_every_collection_endpoint_is_inventoried(app):
    """``_COUNTABLE_PREFIX`` exists so singletons do not clutter the table with
    a meaningless "1". The risk is the opposite mistake: an endpoint holding
    many objects that the list forgets, which then never appears at all.

    So the list polices itself — anything the harvest shows more than one
    object for must be covered.
    """
    aid = _adc(app)
    many = [(A._VS, dict(LIVE_VS, mkey="vs-a"), None),
            (A._VS, dict(LIVE_VS, mkey="vs-b"), None)]
    _ingest(app, aid, many)
    with app.app_context():
        counts = A._cached([aid])
        rows = {r["endpoint"] for r in A.inventory([_appl(app, aid)])["rows"]}
    for (_a, name), n in counts.items():
        if n > 1:
            assert name in rows, (
                "%r holds %d objects but no inventory row covers it — add its "
                "prefix to _COUNTABLE_PREFIX" % (name, n))


def test_unharvested_registry_endpoints_sink_below_the_real_sections(app):
    """They land in section "Other" and would otherwise sort into the MIDDLE,
    burying the sections that hold objects behind ~100 zero rows."""
    aid = _adc(app)
    _ingest(app, aid, [(A._VS, LIVE_VS, None)])
    with app.app_context():
        rows = A.inventory([_appl(app, aid)])["rows"]
    sections = [r["section"] for r in rows]
    if "Other" in sections and len(set(sections)) > 1:
        first_other = sections.index("Other")
        assert all(s == "Other" for s in sections[first_other:])
