"""Guards for the TWO renderers docs.fortinet.com serves, and for the silence
that let one of them go unharvested.

The failure these exist for produced no error anywhere. Fortinet re-rendered the
FortiWeb release notes from MadCap (``mc-main-content``) to a markdown pipeline
(``document-content src-md``) at 8.0.7. ``has_release_content()`` looked for the
MadCap container, did not find it, and the scanner did what it had always done
with a page it could not read: ``continue``. Every scan afterwards finished
green, the progress log said *"8.0.7 — no release notes found"*, and the corpus
silently stopped two releases short — including the release whose *Supported
upgrade paths* announces a mandatory intermediate hop and a disk prerequisite.

So the guards below are not about parsing markdown. They are about the three
states a page can be in, and about never again collapsing the second into the
first:

  1. **absent**    — the version does not publish this section. Silent, correct.
  2. **unreadable** — it DOES publish it and this parser produced nothing. Loud.
  3. **read**      — parsed.

Fixtures are trimmed from the real bytes: the ``mobile-content`` duplicate is
present because the live src-md pages carry the whole article twice, and a slice
that does not close on it doubles every row.
"""
from __future__ import annotations

import time

from app.services import release_notes as rn
from tests.conftest import login, make_user, profile_id

# --------------------------------------------------------------------------- #
#  Fixtures — the three page shapes, in the shape the live pages have           #
# --------------------------------------------------------------------------- #
_MD_RESOLVED = """
<html><body><nav>chrome 8.0.7 | 8.0.6</nav>
<div class="document-content src-md ">
  <h1>Resolved issues</h1>
  <table>
    <thead><tr><th>Bug ID</th><th>Description</th></tr></thead>
    <tbody>
      <tr><td>901234</td><td>SSL handshake fails after a certificate renewal.</td></tr>
      <tr><td>905678</td><td>HA sync stalls. Workaround: restart the daemon.</td></tr>
    </tbody>
  </table>
</div>
<div class="mobile-content"><div class="document-content src-md">
  <h1>Resolved issues</h1>
  <table>
    <thead><tr><th>Bug ID</th><th>Description</th></tr></thead>
    <tbody><tr><td>901234</td><td>SSL handshake fails after a certificate renewal.</td></tr></tbody>
  </table>
</div></div>
</body></html>
"""

_MD_KNOWN_EMPTY = """
<html><body><div class="document-content src-md">
  <h1>Known issues</h1>
  <p>There are no known issues in version 8.0.7.</p>
</div>
<div class="mobile-content"><div class="document-content src-md">x</div></div></body></html>
"""

_MD_PROSE = """
<html><body><div class="document-content src-md">
  <h1>Supported upgrade paths</h1>
  <p>If you are upgrading from a version that is 7.6.1 or lower, then you will
     need to upgrade to version 7.6.2 before proceeding.</p>
</div>
<div class="mobile-content"><div class="document-content src-md">
  <h1>Supported upgrade paths</h1></div></div></body></html>
"""

#: A 200 landing for a version that publishes nothing. The real one is ~442 KB of
#: nav chrome and — this is the whole discriminator — has NO article wrapper.
_LANDING = """
<html><body><nav>FortiWeb 8.0.7 | 8.0.6 | 7.6.10</nav>
<div class="panel-content p-2"><div class="contents py-md-2">
  <a href="/document/fortiweb/8.0.6/release-notes/91537/resolved-issues">Resolved issues</a>
</div></div></body></html>
"""

#: An article in a renderer this parser has never seen. THE case that broke.
_FUTURE_RENDERER = _MD_RESOLVED.replace("src-md", "src-xyzzy")


def _fetch_map(mapping, default=_LANDING):
    def fetch(url: str) -> str:
        for needle, html in mapping.items():
            if needle in url:
                return html
        return default
    return fetch


# --------------------------------------------------------------------------- #
#  The three states                                                             #
# --------------------------------------------------------------------------- #
def test_a_landing_page_is_not_an_article():
    assert not rn.has_article(_LANDING)
    assert not rn.has_release_content(_LANDING)


def test_a_madcap_page_is_an_article_even_without_the_generic_wrapper():
    """Recognising a container IS proof there is an article.

    Making the generic ``document-content`` wrapper the sole evidence would skip
    a page we can read perfectly well, in silence, the day Fortinet drop it —
    the same bug in the opposite direction."""
    html = '<div id="mc-main-content"><table><tr><th>Bug ID</th></tr></table></div>'
    assert rn.has_article(html)
    assert rn.has_release_content(html)


def test_an_unknown_renderer_is_an_article_we_cannot_read():
    """The exact 8.0.7 state, and the one that used to be indistinguishable
    from 'this version has no release notes'."""
    assert rn.has_article(_FUTURE_RENDERER)
    assert not rn.has_release_content(_FUTURE_RENDERER)


# --------------------------------------------------------------------------- #
#  src-md parsing                                                               #
# --------------------------------------------------------------------------- #
def test_src_md_issue_table_is_parsed():
    rows = rn.parse_issue_table(_MD_RESOLVED)
    assert [r[0] for r in rows] == ["901234", "905678"]


def test_the_mobile_duplicate_is_not_harvested_twice():
    """The live src-md pages repeat the whole article inside ``mobile-content``.

    Slicing to the end of the document would double every paragraph — and a
    doubled corpus reads like a correct one."""
    text = rn.parse_section_text(_MD_PROSE)
    assert text.count("Supported upgrade paths") == 1, text


def test_src_md_prose_is_extracted():
    text = rn.parse_section_text(_MD_PROSE)
    assert "7.6.1 or lower" in text
    assert "upgrade to version 7.6.2" in text


# --------------------------------------------------------------------------- #
#  The guard: published-but-unreadable is REPORTED, never skipped               #
# --------------------------------------------------------------------------- #
def test_an_unreadable_article_is_recorded_and_announced():
    lines = []
    db = rn.scan_release_notes(_fetch_map({"resolved-issues": _FUTURE_RENDERER}),
                               ["8.0.9"], sections=("resolved",),
                               on_progress=lines.append)
    assert len(db.unreadable) == 1
    u = db.unreadable[0]
    assert (u.version, u.section) == ("8.0.9", "resolved")
    assert u.url.endswith("/resolved-issues")
    assert any("UNREADABLE" in ln for ln in lines), lines
    # and it must NOT be counted as harvested — a version we could not read is
    # not a version we have.
    assert db.versions == []


def test_an_absent_version_stays_silent():
    """The only branch allowed to be quiet. 7.0.x–7.4.x resolve to landings, and
    a scan that shouted about each of them would train the operator to ignore
    the shout that matters."""
    lines = []
    db = rn.scan_release_notes(_fetch_map({}), ["7.0.3"], sections=("resolved",),
                               on_progress=lines.append)
    assert db.unreadable == []
    assert any("no release notes found" in ln for ln in lines), lines


def test_an_issues_page_that_says_it_is_empty_is_a_successful_read():
    """8.0.7 genuinely has no known issues and says so in prose.

    Without this, 'the table is empty' and 'I could not read the table' are the
    same observation — and one of them is a broken parser."""
    lines = []
    db = rn.scan_release_notes(_fetch_map({"known-issues": _MD_KNOWN_EMPTY}),
                               ["8.0.7"], sections=("known",),
                               on_progress=lines.append)
    assert db.unreadable == []
    assert db.issues == []
    assert db.versions == ["8.0.7"], "an empty-but-read version is still read"


def test_an_issues_page_with_no_table_and_no_statement_is_unreadable():
    """The inverse of the test above, and the reason it is not enough to check
    for an empty table: a page with prose but no readable table is a parser
    failure wearing the costume of an empty release."""
    broken = _MD_KNOWN_EMPTY.replace(
        "There are no known issues in version 8.0.7.",
        "This page lists the issues present in this version.")
    db = rn.scan_release_notes(_fetch_map({"known-issues": broken}),
                               ["8.0.7"], sections=("known",))
    assert len(db.unreadable) == 1
    assert db.unreadable[0].section == "known"


def test_an_empty_prose_article_is_unreadable():
    empty = '<div class="document-content src-md"></div>'
    db = rn.scan_release_notes(_fetch_map({"upgrade-notes": empty}),
                               ["8.0.7"], sections=("upgrade_notes",))
    assert len(db.unreadable) == 1


# --------------------------------------------------------------------------- #
#  The rest of the Upgrade instructions branch                                  #
# --------------------------------------------------------------------------- #
def test_the_whole_upgrade_instructions_branch_is_harvested():
    """The five sections that were never collected.

    ``upgrading_from`` and ``upgrade_notes`` are SIBLINGS of these, not parents,
    so harvesting the two left the blocking prerequisites — repartition, HA
    order, downgrade support, VM licensing — out of the corpus entirely."""
    for key in ("repartitioning", "ha_upgrade", "downgrading", "image_checksums",
                "vm_license"):
        assert key in rn.SECTIONS_BY_PRODUCT["fortiweb"], key
        assert key in rn.PROSE_SECTIONS, key
        assert key in rn.SECTION_LABEL, key
        assert key in rn.DEFAULT_SECTIONS, key


def test_the_upgrade_subset_excludes_whats_new_and_the_support_matrix():
    """``UPGRADE_SECTIONS`` is what the advisor reads. Widening it to every prose
    section would pour the what's-new list into an upgrade verdict."""
    assert "whats_new" not in rn.UPGRADE_SECTIONS
    assert "product_integration" not in rn.UPGRADE_SECTIONS
    assert set(rn.UPGRADE_SECTIONS) <= set(rn.PROSE_SECTIONS)


def test_fortiadc_is_not_given_fortiweb_doc_ids():
    """The ids are per product. Pointing FortiWeb's at FortiADC 302-redirects to
    the wrong page, which is the worst possible outcome: content, for the wrong
    product, under the right label."""
    adc = rn.SECTIONS_BY_PRODUCT["fortiadc"]
    for key in ("repartitioning", "ha_upgrade", "downgrading", "vm_license"):
        assert key not in adc, key


def test_a_product_without_a_section_skips_it_rather_than_404ing():
    lines = []
    rn.scan_release_notes(_fetch_map({}), ["8.0.3"], product="fortiadc",
                          sections=("repartitioning",), on_progress=lines.append)
    assert not any("UNREADABLE" in ln for ln in lines), lines


# --------------------------------------------------------------------------- #
#  Giving up on a version that publishes nothing — cheaply, and out loud        #
# --------------------------------------------------------------------------- #
def _counting_fetch(mapping):
    """A fetcher that records every URL it was asked for."""
    calls = []

    def fetch(url: str) -> str:
        calls.append(url)
        for needle, html in mapping.items():
            if needle in url:
                return html
        return _LANDING
    return fetch, calls


def test_a_version_that_publishes_nothing_is_not_probed_eleven_times():
    """Cost, and it is a cost this round introduced.

    47 of the 59 versions the docs site lists publish nothing, and each answers
    every section with the same ~442 KB landing. Adding the five upgrade sections
    took a full sweep from six fetches per dead version to eleven."""
    fetch, calls = _counting_fetch({})
    lines = []
    rn.scan_release_notes(fetch, ["7.0.3"], on_progress=lines.append)
    # exactly the probes, and not one page more: the break happens BEFORE
    # the fetch that would have been the third.
    assert len(calls) == rn.PROBES_BEFORE_GIVING_UP, calls
    assert any("gave up" in ln for ln in lines), lines


def test_giving_up_is_announced_and_never_silent():
    """A shortcut that is not stated is a coverage claim nobody can check."""
    fetch, _ = _counting_fetch({})
    lines = []
    rn.scan_release_notes(fetch, ["7.0.3"], on_progress=lines.append)
    assert any(str(rn.PROBES_BEFORE_GIVING_UP) in ln and "gave up" in ln
               for ln in lines), lines


def test_one_article_cancels_the_give_up_for_the_whole_version():
    """THE risk of the shortcut: dropping ten sections because one was missing.

    Driven, not reasoned: the first section is a landing, the second an article,
    and the remaining sections must still be fetched."""
    fetch, calls = _counting_fetch({"resolved-issues": _MD_RESOLVED})
    db = rn.scan_release_notes(fetch, ["8.0.7"])
    assert db.versions == ["8.0.7"]
    # every section of the map was asked for — nothing was skipped
    assert len(calls) == len(rn.DEFAULT_SECTIONS), (len(calls), len(rn.DEFAULT_SECTIONS))


def test_the_give_up_never_applies_once_something_has_been_found():
    """A real release with a run of sections it does not carry must not be cut
    short after what it DID publish."""
    fetch, calls = _counting_fetch({"known-issues": _MD_KNOWN_EMPTY})
    db = rn.scan_release_notes(fetch, ["8.0.7"])
    assert db.versions == ["8.0.7"], "the empty-but-read page still counts as found"
    assert len(calls) == len(rn.DEFAULT_SECTIONS), calls


def test_an_unreadable_first_probe_does_not_count_as_blank():
    """'I could not read it' must never be spent as evidence that the version is
    absent — that is the original bug, wearing a stopwatch."""
    fetch, calls = _counting_fetch({"known-issues": _FUTURE_RENDERER,
                                    "resolved-issues": _FUTURE_RENDERER})
    db = rn.scan_release_notes(fetch, ["8.0.9"])
    assert len(db.unreadable) >= 2
    assert len(calls) == len(rn.DEFAULT_SECTIONS), calls


# --------------------------------------------------------------------------- #
#  Routes: discovery, and the contradiction that can no longer be submitted     #
# --------------------------------------------------------------------------- #
def _admin(app):
    return make_user(app, "rndadmin", role="admin", profile_id=profile_id(app, "admin"))


def _viewer(app):
    return make_user(app, "rndview", role="readonly",
                     profile_id=profile_id(app, "readonly"))


def _seed(app, db):
    from app.views.release_notes import _corpus_root
    with app.app_context():
        rn.save_db(db, root=_corpus_root())


def test_discover_marks_what_the_corpus_already_holds(app, client, monkeypatch):
    monkeypatch.setattr(rn, "make_fetcher", lambda **k: _fetch_map({}))
    monkeypatch.setattr(rn, "discover_versions",
                        lambda fetch, **k: ["8.0.5", "8.0.6", "8.0.7"])
    _seed(app, rn.scan_release_notes(
        _fetch_map({"resolved-issues": _MD_RESOLVED}), ["8.0.5"],
        sections=("resolved",)))
    login(client, _admin(app))
    d = client.post("/release-notes/discover", json={"use_direct": True}).get_json()
    got = {r["version"]: r["in_corpus"] for r in d["versions"]}
    assert got == {"8.0.7": False, "8.0.6": False, "8.0.5": True}
    assert d["new"] == 2
    assert [r["version"] for r in d["versions"]] == ["8.0.7", "8.0.6", "8.0.5"], \
        "newest first — the one an operator is looking for is at the top"


def test_discover_is_admin_only(app, client, monkeypatch):
    monkeypatch.setattr(rn, "discover_versions", lambda fetch, **k: ["8.0.7"])
    login(client, _viewer(app))
    assert client.post("/release-notes/discover", json={}).status_code == 403


def test_discovery_that_returns_nothing_is_an_error_not_an_empty_list(app, client,
                                                                     monkeypatch):
    """An empty picker with a green tick would read as 'Fortinet publish no
    versions'. It means we could not ask."""
    monkeypatch.setattr(rn, "make_fetcher", lambda **k: _fetch_map({}))
    monkeypatch.setattr(rn, "discover_versions", lambda fetch, **k: [])
    login(client, _admin(app))
    r = client.post("/release-notes/discover", json={"use_direct": True})
    assert r.status_code == 502
    assert "unreachable" in r.get_json()["error"].lower()


def test_an_explicit_version_list_is_scanned_verbatim(app, client, monkeypatch):
    """THE fix for the reported behaviour.

    The operator asked for one line and got all 59 versions. Discovery is now a
    suggestion; the ticks are the order, and nothing re-derives them."""
    seen = {}

    def fake_scan(fetch, versions, **kw):
        seen["versions"] = list(versions)
        return rn.ReleaseNotesDB(generated_at="x")

    monkeypatch.setattr(rn, "make_fetcher", lambda **k: _fetch_map({}))
    monkeypatch.setattr(rn, "discover_versions",
                        lambda fetch, **k: ["7.0.1", "8.0.5", "8.0.6", "8.0.7"])
    monkeypatch.setattr(rn, "scan_release_notes", fake_scan)
    login(client, _admin(app))
    r = client.post("/release-notes/scan",
                    json={"versions": ["8.0.7"], "use_direct": True, "publish": False})
    assert r.status_code == 202
    for _ in range(60):
        if not client.get("/release-notes/scan/status").get_json().get("running"):
            break
        time.sleep(0.1)
    assert seen.get("versions") == ["8.0.7"], seen


def test_an_empty_explicit_list_is_refused(app, client):
    login(client, _admin(app))
    r = client.post("/release-notes/scan", json={"versions": []})
    assert r.status_code == 400


def test_all_and_a_majors_filter_can_no_longer_disagree_in_silence(app, client):
    """The precise shape of the reported bug.

    '8.0' sat typed in the box while 'All discovered' was ticked; the checkbox
    won, 59 versions were harvested, and nothing anywhere said which control had
    decided. A contradiction now fails to submit instead of resolving itself."""
    login(client, _admin(app))
    r = client.post("/release-notes/scan", json={"all": True, "majors": "8.0"})
    assert r.status_code == 400
    assert "contradict" in r.get_json()["error"].lower()


def test_an_explicit_list_cannot_be_mixed_with_the_legacy_filter(app, client):
    login(client, _admin(app))
    r = client.post("/release-notes/scan",
                    json={"versions": ["8.0.7"], "majors": "8.0"})
    assert r.status_code == 400


def test_the_legacy_majors_path_still_works(app, client, monkeypatch):
    """Kept on purpose: the API is used by tests and by anything scripted against
    it. The UI stopped offering the contradiction; the endpoint did not stop
    accepting a single unambiguous filter."""
    seen = {}

    def fake_scan(fetch, versions, **kw):
        seen["versions"] = list(versions)
        return rn.ReleaseNotesDB(generated_at="x")

    monkeypatch.setattr(rn, "make_fetcher", lambda **k: _fetch_map({}))
    monkeypatch.setattr(rn, "discover_versions",
                        lambda fetch, **k: ["7.0.1", "8.0.6", "8.0.7"])
    monkeypatch.setattr(rn, "scan_release_notes", fake_scan)
    login(client, _admin(app))
    assert client.post("/release-notes/scan",
                       json={"majors": "8.0", "publish": False}).status_code == 202
    for _ in range(60):
        if not client.get("/release-notes/scan/status").get_json().get("running"):
            break
        time.sleep(0.1)
    assert seen.get("versions") == ["8.0.6", "8.0.7"], seen


def test_a_scan_that_could_not_read_a_page_does_not_report_success(app, client,
                                                                   monkeypatch):
    """End to end: the unreadable record has to reach the operator.

    A result that carries the harvest and hides the gap is the failure this
    whole file exists for, one layer up."""
    monkeypatch.setattr(rn, "make_fetcher",
                        lambda **k: _fetch_map({"resolved-issues": _FUTURE_RENDERER}))
    monkeypatch.setattr(rn, "discover_versions", lambda fetch, **k: ["8.0.9"])
    login(client, _admin(app))
    assert client.post("/release-notes/scan",
                       json={"versions": ["8.0.9"], "publish": False}).status_code == 202
    st = None
    for _ in range(60):
        st = client.get("/release-notes/scan/status").get_json()
        if not st.get("running"):
            break
        time.sleep(0.1)
    assert st and st.get("error") is None
    unread = (st.get("result") or {}).get("unreadable")
    assert unread, st
    assert unread[0]["version"] == "8.0.9"
    assert any("INCOMPLETE" in ln for ln in st.get("lines", [])), st.get("lines")

    from app.models import User
    from app.models_notifications import Notification
    with app.app_context():
        uid = User.query.filter_by(username="rndadmin").first().id
        rows = Notification.query.filter_by(user_id=uid).all()
    assert rows, "no bell notification"
    assert any(n.kind == "warning" and "INCOMPLETE" in (n.title or "")
               for n in rows), [(n.kind, n.title) for n in rows]
    assert not any(n.kind == "success" for n in rows), \
        "a scan that could not read a published page must never light a success bell"
