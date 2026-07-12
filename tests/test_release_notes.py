"""Release Notes — pure harvester (services.release_notes) + the web routes.

The service tests are ported verbatim from the desktop app (it is the same
Qt-free module); the route tests exercise the modal's JSON backend against an
isolated corpus (never the live reports/_release_notes.json) and verify the
admin gate on Scan. No network: the scan route is monkeypatched at the fetch
boundary.
"""
from __future__ import annotations

import time

from app.services import release_notes as rn
from tests.conftest import login, make_user, profile_id


# =========================================================================== #
#  Pure service tests (ported from desktop tests/test_release_notes.py)         #
# =========================================================================== #
_RESOLVED_HTML = """
<html><body><nav>chrome 8.0.5 | 8.0.4 | 7.6.8</nav>
<div id="mc-main-content" role="main">
  <h1>Resolved issues</h1>
  <table>
    <thead><tr><th>Bug ID</th><th>Description</th></tr></thead>
    <tbody>
      <tr><td>111111</td><td>SSL certificate handshake fails on FDS connections.</td></tr>
      <tr><td>222222</td><td>HA secondary loses its config after sync.</td></tr>
    </tbody>
  </table>
</div>
<div id="mc-footer">footer</div></body></html>
"""

_KNOWN_HTML = """
<html><body>
<div id="mc-main-content">
  <table>
    <tr><th>Bug ID</th><th>Description</th></tr>
    <tr><td>333333</td><td>GUI dashboard fails to load. Workaround: refresh the page.</td></tr>
  </table>
</div></body></html>
"""

_PROSE_HTML = """
<html><body><nav>8.0.5 | 8.0.4 | versions list chrome</nav>
<div id="mc-main-content"><h1>Upgrade notes</h1>
<p>Upgrading to 8.0.5 may require re-applying the GeoIP database.</p>
<ul><li>Back up first.</li><li>Reboot after.</li></ul>
</div><div id="mc-footer">x</div></body></html>
"""

_FALLBACK_HTML = """
<html><body><nav>Release Notes FortiWeb 7.4.5
8.0.5 | 8.0.4 | 7.6.9 | 7.6.8 | 7.4.5</nav></body></html>
"""


def test_version_key_orders_correctly():
    assert rn.version_key("8.0.4") == "0008.0000.0004"
    versions = ["7.6.10", "7.6.2", "8.0.0", "7.6.9", "10.0.1"]
    assert sorted(versions, key=rn.version_key) == \
        ["7.6.2", "7.6.9", "7.6.10", "8.0.0", "10.0.1"]
    assert rn.version_tuple("8.0.5") == (8, 0, 5)
    assert rn.major_of("8.0.5") == "8.0"


def test_select_versions_filters_by_major():
    vs = ["7.6.8", "8.0.0", "8.0.5", "7.4.1"]
    assert rn.select_versions(vs, ["8.0"]) == ["8.0.0", "8.0.5"]
    assert rn.select_versions(vs, None) == vs


def test_discover_versions_floors_pre_modern_majors():
    """The seed page's version-history dropdown lists ancient lines (5.x/6.x) that
    have no resolved/known-issues pages; discovery must drop them so a full ("All")
    scan never grinds through dead versions — only modern (>= 7.0) lines survive."""
    html = (
        '<a href="/document/fortiweb/5.0.0/release-notes/x/y">5.0.0</a>'
        '<a href="/document/fortiweb/5.4.0/release-notes/x/y">5.4.0</a>'
        '<a href="/document/fortiweb/6.4.3/release-notes/x/y">6.4.3</a>'
        '<a href="/document/fortiweb/7.0.0/release-notes/x/y">7.0.0</a>'
        '<a href="/document/fortiweb/8.0.5/release-notes/x/y">8.0.5</a>'
    )
    got = rn.discover_versions(lambda url: html)
    assert got == ["7.0.0", "8.0.5"]
    # explicit override still honored
    assert rn.discover_versions(lambda url: html, min_version=(6, 0)) == \
        ["6.4.3", "7.0.0", "8.0.5"]


def test_parse_issue_table():
    rows = rn.parse_issue_table(_RESOLVED_HTML)
    assert rows == [
        ("111111", "SSL certificate handshake fails on FDS connections."),
        ("222222", "HA secondary loses its config after sync."),
    ]
    assert rn.parse_issue_table(_KNOWN_HTML)[0][0] == "333333"


def test_parse_issue_table_ignores_fallback():
    assert rn.parse_issue_table(_FALLBACK_HTML) == []
    assert rn.has_release_content(_FALLBACK_HTML) is False
    assert rn.has_release_content(_RESOLVED_HTML) is True


def test_split_workaround():
    main, wa = rn.split_workaround("GUI dashboard fails to load. Workaround: refresh the page.")
    assert "GUI dashboard fails" in main
    assert wa == "refresh the page."
    assert rn.split_workaround("no workaround here") == ("no workaround here", "")


def test_prose_extraction_strips_chrome():
    txt = rn.parse_section_text(_PROSE_HTML)
    assert "Upgrading to 8.0.5" in txt
    assert "Back up first." in txt
    assert "versions list chrome" not in txt
    assert rn.parse_section_text(_FALLBACK_HTML) == ""


def test_classify_topic_curated():
    assert rn.classify_topic("SSL certificate revoked") == "SSL/TLS & Certificates"
    assert rn.classify_topic("HA cluster failover broke") == "High Availability"
    assert rn.classify_topic("RADIUS login with MFA fails") == "Authentication & SSO"
    assert rn.classify_topic("The GeoIP database is lost") == "GeoIP & IP Reputation"
    assert rn.classify_topic("something totally unrelated xyzzy") == "General"


def _fake_fetch(url: str) -> str:
    if "resolved-issues" in url and "8.0.5" in url:
        return _RESOLVED_HTML
    if "known-issues" in url and "8.0.5" in url:
        return _KNOWN_HTML
    if "upgrade-notes" in url and "8.0.5" in url:
        return _PROSE_HTML
    raise rn.NotFound(url)


def test_scan_release_notes_with_fake_fetcher():
    db = rn.scan_release_notes(_fake_fetch, ["8.0.5"])
    assert db.versions == ["8.0.5"]
    assert len(db.issues) == 3
    assert {i.status for i in db.issues} == {"resolved", "known"}
    assert any(s.section == "upgrade_notes" for s in db.sections)
    known = next(i for i in db.issues if i.status == "known")
    assert known.workaround == "refresh the page."
    assert known.topic == "GUI / Web UI"


def test_scan_skips_missing_versions():
    db = rn.scan_release_notes(_fake_fetch, ["7.0.0"])
    assert db.versions == [] and db.issues == []


def test_merge_db_replaces_version_keeps_others():
    old = rn.ReleaseNotesDB(
        generated_at="t0", versions=["7.6.8", "8.0.5"],
        issues=[rn.ReleaseIssue("fortiweb", "7.6.8", "resolved", "1", "old", "", "", ""),
                rn.ReleaseIssue("fortiweb", "8.0.5", "resolved", "2", "stale", "", "", "")],
        sections=[])
    merged = rn.merge_db(old, rn.scan_release_notes(_fake_fetch, ["8.0.5"]))
    assert set(merged.versions) == {"7.6.8", "8.0.5"}
    assert any(i.version == "7.6.8" and i.bug_id == "1" for i in merged.issues)
    assert not any(i.bug_id == "2" for i in merged.issues)


def _issues():
    return [
        rn.ReleaseIssue("fortiweb", "7.6.8", "resolved", "100", "fixed in 7.6.8", "", "", ""),
        rn.ReleaseIssue("fortiweb", "8.0.3", "resolved", "200", "fixed in 8.0.3", "", "", ""),
        rn.ReleaseIssue("fortiweb", "8.0.5", "resolved", "300", "fixed in 8.0.5", "", "", ""),
        rn.ReleaseIssue("fortiweb", "8.0.5", "known", "400", "known in 8.0.5", "", "", ""),
    ]


def test_advise_resolved_in_range_and_known_in_target():
    secs = [rn.ReleaseSection("fortiweb", "8.0.3", "upgrade_notes", "Notes", "do x", "")]
    adv = rn.advise(_issues(), secs, "7.6.8", "8.0.5")
    assert adv.is_upgrade is True
    assert {i.bug_id for i in adv.resolved} == {"200", "300"}
    assert {i.bug_id for i in adv.known_in_target} == {"400"}
    assert len(adv.notes) == 1


def test_advise_downgrade_flag():
    assert rn.advise(_issues(), [], "8.0.5", "7.6.8").is_upgrade is False


def test_save_load_roundtrip(tmp_path):
    db = rn.scan_release_notes(_fake_fetch, ["8.0.5"])
    rn.save_db(db, root=tmp_path)
    got = rn.load_db(root=tmp_path)
    assert got is not None
    assert got.versions == ["8.0.5"]
    assert len(got.issues) == 3


# =========================================================================== #
#  Web route tests                                                             #
# =========================================================================== #
def _admin(app):
    return make_user(app, "rnadmin", role="admin", profile_id=profile_id(app, "admin"))


def _viewer(app):
    return make_user(app, "rnview", role="readonly", profile_id=profile_id(app, "readonly"))


def _seed(app, db):
    from app.views.release_notes import _corpus_root
    with app.app_context():
        rn.save_db(db, root=_corpus_root())


def test_data_and_issues_for_viewer(app, client):
    _seed(app, rn.scan_release_notes(_fake_fetch, ["8.0.5"]))
    login(client, _viewer(app))
    d = client.get("/release-notes/data").get_json()
    assert d["counts"]["issues"] == 3
    assert d["is_admin"] is False
    assert "8.0.5" in d["versions"]
    rows = client.get("/release-notes/issues?status=known").get_json()
    assert rows["count"] == 1
    assert rows["issues"][0]["bug_id"] == "333333"


def test_advise_route(app, client):
    db = rn.ReleaseNotesDB(generated_at="t", versions=["7.6.8", "8.0.3", "8.0.5"],
                           issues=_issues(), sections=[])
    _seed(app, db)
    login(client, _viewer(app))
    d = client.get("/release-notes/advise?current=7.6.8&target=8.0.5").get_json()
    assert d["is_upgrade"] is True
    assert {i["bug_id"] for i in d["resolved"]} == {"200", "300"}
    # same version → 400
    assert client.get("/release-notes/advise?current=8.0.5&target=8.0.5").status_code == 400


def test_notes_route(app, client):
    db = rn.scan_release_notes(_fake_fetch, ["8.0.5"])
    _seed(app, db)
    login(client, _viewer(app))
    d = client.get("/release-notes/notes?q=geoip").get_json()
    assert d["count"] >= 1
    assert "GeoIP" in d["sections"][0]["content"]


def test_scan_gate_readonly_403_admin_202(app, client, monkeypatch):
    # no network: patch the fetch + discovery + scan boundary
    monkeypatch.setattr(rn, "make_fetcher", lambda **k: _fake_fetch)
    monkeypatch.setattr(rn, "discover_versions", lambda fetch, **k: ["8.0.5"])

    login(client, _viewer(app))
    assert client.post("/release-notes/scan", json={"all": True}).status_code == 403

    login(client, _admin(app))
    r = client.post("/release-notes/scan",
                    json={"all": True, "use_direct": True, "publish": False})
    assert r.status_code == 202

    # poll status until the background thread finishes
    result = None
    for _ in range(50):
        st = client.get("/release-notes/scan/status").get_json()
        if not st.get("running"):
            result = st
            break
        time.sleep(0.1)
    assert result is not None, "scan never finished"
    assert result.get("error") is None
    assert result["result"]["scanned"] == 1
    assert result["result"]["new_issues"] == 3


def test_sync_route(app, client):
    _seed(app, rn.scan_release_notes(_fake_fetch, ["8.0.5"]))
    login(client, _viewer(app))
    d = client.post("/release-notes/sync").get_json()
    assert d["counts"]["issues"] == 3


def test_release_notes_reachable_in_fortiadc_adom(app, client, monkeypatch):
    """Regression (2026-07-12): the ADC ADOM top-banner Release-Notes modal must
    reach the blueprint. ``_product_gate`` only allows an allowlist of blueprints
    in the FortiADC ADOM; ``release_notes`` was missing, so every
    ``/release-notes/*`` call 302-redirected to ``adc.index`` and the scan
    silently no-opped (the browser followed the redirect to an HTML page)."""
    monkeypatch.setattr(rn, "make_fetcher", lambda **k: _fake_fetch)
    monkeypatch.setattr(rn, "discover_versions", lambda fetch, **k: ["8.0.5"])
    _seed(app, rn.scan_release_notes(_fake_fetch, ["8.0.5"]))
    login(client, _admin(app), product="fortiadc")

    # read endpoint must be served, not redirected out of the ADOM
    r = client.get("/release-notes/data")
    assert r.status_code == 200, "release-notes bounced out of the FortiADC ADOM"

    # and the scan endpoint itself must be reachable (202 start / 409 busy), not 302
    r = client.post("/release-notes/scan",
                    json={"all": False, "majors": "8.0",
                          "use_direct": True, "publish": False},
                    headers={"X-ADOM": "fortiadc"})
    assert r.status_code in (202, 409), f"scan gated out of ADC ADOM: {r.status_code}"
