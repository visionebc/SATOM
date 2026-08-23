"""Settings → Sentinel — the dedicated section and its demo lab.

The section's central promise is printed on the page: the demonstrations run
through the LIVE engine and write nothing. Both halves of that sentence are
asserted here, because both are the kind of claim that silently stops being
true — a demo that drifts from the scorer keeps rendering, and a demo that
starts persisting rows poisons the incident statistics it explains.

``expected_band`` in the scenario catalog is a published claim (the page shows
these scenarios to operators): a weight tune that moves a scenario out of its
band must fail here, in the commit that tunes it, not on the Settings page of
the next person who presses the button.
"""
from __future__ import annotations

from conftest import admin_user_id, login

from app.models_sentinel import (SentinelAction, SentinelEvent,
                                 SentinelIncident)
from app.services.sentinel import demo


def _counts(app):
    with app.app_context():
        return (SentinelEvent.query.count(), SentinelIncident.query.count(),
                SentinelAction.query.count())


# --------------------------------------------------------------------------- #
#  The page                                                                     #
# --------------------------------------------------------------------------- #
def test_section_renders_pipeline_weights_form_and_scenarios(app, client):
    login(client, admin_user_id(app))
    r = client.get('/settings/sentinel')
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    # the three layers of explanation, then the form
    assert 'What Sentinel does, stage by stage' in body
    assert 'Policy gates' in body                      # a pipeline stage
    assert 'Subtracts points' in body                  # live weight table
    assert 'ten scenarios against the live engine' in body
    for scen in demo.catalog():
        assert f'data-slug="{scen["slug"]}"' in body, scen["slug"]
    assert 'sn-enabled' in body                        # the generated form
    assert 'settings/sentinel/demo' in body            # the lab is wired


def test_the_settings_pane_renders_the_whole_section_inline(app, client):
    """The pane IS the section now, not a door to it.

    The doorway was one button whose only effect was to leave the console:
    the operator asked for the explanation to sit where the knobs are. So the
    pane has to carry all four layers — pipeline, weights, demo lab, form —
    and nothing may send anyone to another URL to change a setting.
    """
    login(client, admin_user_id(app))
    body = client.get('/settings/').get_data(as_text=True)
    assert 'Open the Sentinel section' not in body, \
        'the pane is a doorway again'
    assert 'What Sentinel does, stage by stage' in body   # the pipeline
    assert 'Subtracts points' in body                     # live weight table
    assert 'ten scenarios against the live engine' in body
    assert 'settings/sentinel/demo' in body               # the lab is wired
    assert 'sn-enabled' in body                           # the generated form


def test_the_form_is_rendered_once_per_page_from_one_template(app, client):
    """One form, one FILE — still.

    Two surfaces render it now, which is fine; two *copies* would not be. A
    hand-written second form in the pane would put a second ``id="sn-enabled"``
    on the same page, and every ``<label for>`` on it would point at the wrong
    input — the failure the doorway was originally chosen to avoid, and the
    one this guard keeps out now that the doorway is gone.
    """
    login(client, admin_user_id(app))
    pane = client.get('/settings/').get_data(as_text=True)
    page = client.get('/settings/sentinel').get_data(as_text=True)
    assert pane.count('id="sn-enabled"') == 1, 'the form is duplicated in the pane'
    assert page.count('id="sn-enabled"') == 1, 'the form is duplicated on the page'


def test_each_surface_tells_the_save_where_it_was_rendered(app, client):
    """The view honours ``return_to``; this asserts the forms actually SEND it.

    Without the field the endpoint's branch is unreachable and every save
    lands on the standalone page again — the view-level guard would keep
    passing, because a test can post a value a browser never would.
    """
    login(client, admin_user_id(app))
    pane = client.get('/settings/').get_data(as_text=True)
    page = client.get('/settings/sentinel').get_data(as_text=True)
    assert 'name="return_to" value="pane"' in pane, \
        'the pane form does not say it was rendered in the pane'
    assert 'name="return_to" value="page"' in page, \
        'the standalone form does not say it was rendered on the page'


def test_a_save_from_the_pane_comes_back_to_the_pane(app, client):
    """Saving must not move the operator out of the console they were in.

    Both surfaces post to the same endpoint, so the form says where it was
    rendered; without that the pane's save would land on the standalone page
    and undo, at the one moment it matters, the whole point of inlining it.
    """
    login(client, admin_user_id(app))
    r = client.post('/settings/sentinel',
                    data={'csrf_token': 'x', 'return_to': 'pane'},
                    follow_redirects=False)
    assert r.status_code == 302
    assert r.headers['Location'].endswith('/settings/#tab-sentinel'), \
        r.headers['Location']


def test_save_redirects_back_to_the_section(app, client):
    login(client, admin_user_id(app))
    r = client.post('/settings/sentinel', data={'csrf_token': 'x'},
                    follow_redirects=False)
    assert r.status_code == 302
    assert '/settings/sentinel' in r.headers['Location']


# --------------------------------------------------------------------------- #
#  The demo lab                                                                 #
# --------------------------------------------------------------------------- #
def test_every_scenario_runs_and_lands_in_its_published_band(app, client):
    login(client, admin_user_id(app))
    for scen in demo.catalog():
        r = client.get(f'/settings/sentinel/demo/{scen["slug"]}')
        assert r.status_code == 200, scen["slug"]
        data = r.get_json()
        assert 0 <= data['score'] <= 100
        assert data['band'] == scen['expected_band'], (
            f'{scen["slug"]} published band {scen["expected_band"]!r} but the '
            f'live engine produced {data["band"]!r} (score {data["score"]}) — '
            f'update the catalog in the same commit as the weight change')
        assert data['simulated'] is True
        assert data['factors'] is not None
        assert data['gates']['checks'], 'gate audit must be present'


def test_the_demo_writes_nothing(app, client):
    login(client, admin_user_id(app))
    before = _counts(app)
    for scen in demo.catalog():
        assert client.get(
            f'/settings/sentinel/demo/{scen["slug"]}').status_code == 200
    assert _counts(app) == before, (
        'a demo run persisted rows — it must never touch the incident tables')


def test_gate_audit_reads_the_live_kill_switch(app, client):
    """A fresh install is disarmed; the audit must SAY so rather than show a
    canned pass. This is what makes the audit worth reading."""
    login(client, admin_user_id(app))
    data = client.get('/settings/sentinel/demo/dos-like').get_json()
    ks = next(c for c in data['gates']['checks'] if c['check'] == 'kill_switch')
    assert ks['ok'] is False
    assert data['gates']['allowed'] is False


def test_unknown_scenario_is_a_404_not_a_guess(app, client):
    login(client, admin_user_id(app))
    assert client.get('/settings/sentinel/demo/nope').status_code == 404


def test_pseudo_incident_band_matches_the_model(app, client):
    """``demo.run`` hands the policy engine a stand-in with a precomputed
    band. If ``band_of`` and ``SentinelIncident.band`` ever disagree, the
    stand-in lies to :func:`actions.recommend` — catch the drift here."""
    login(client, admin_user_id(app))
    for scen in demo.catalog():
        data = client.get(f'/settings/sentinel/demo/{scen["slug"]}').get_json()
        model_band = SentinelIncident(score=data['score']).band
        # the model has no 0-39 name of its own below observe; both sides map
        # score -> band with the same thresholds, so they must agree verbatim
        assert data['band'] == model_band, scen['slug']


def test_context_beats_identical_evidence(app, client):
    """The catalog keeps the suite's flagship pair: the authorised scanner
    carries the same attack evidence as the hostile flood and must land far
    below it — context, not evidence, separates them."""
    login(client, admin_user_id(app))
    hostile = client.get('/settings/sentinel/demo/dos-like').get_json()
    friendly = client.get(
        '/settings/sentinel/demo/authorised-scanner').get_json()
    assert friendly['score'] < hostile['score'] - 40
    fired = {f['factor'] for f in friendly['factors']}
    assert 'trusted_source' in fired and 'maintenance_window' in fired


# --------------------------------------------------------------------------- #
#  Discoverability                                                              #
# --------------------------------------------------------------------------- #
def test_the_section_is_on_the_concept_map(app):
    from app.services import concept_map
    assert any(p['endpoint'] == 'settings.sentinel_section'
               for p in concept_map.PAGES)
