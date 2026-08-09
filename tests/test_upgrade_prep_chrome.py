"""Upgrade-preparation page: light chrome, contained values, readable CLI output.

Reported 2026-08-10: on ``/appliances/<id>/upgrade/prep`` the result text ran
past the card edges, the sizing did not match the rest of the product, and the
device CLI output "no se ve por los colores".

Three distinct defects, none of which can ever raise:

1. ``.fw-pre`` was a DARK-THEME LEFTOVER. ``rgba(0,0,0,0.30)`` over a white card
   renders as a light-grey slab, and ``#94a3b8`` text on that slab is about
   1.3:1 -- the health battery was rendered, complete, and unreadable. It is the
   same class of defect as the status pills fixed on 2026-07-28 (safeguards 9m),
   and ``.fw-pre`` is shared by FIVE other templates, so the same invisible
   output was on the inspector JSON dump, the git console in settings and the
   formal change-request document.
2. The four result tiles put device strings -- a firmware build, a backup
   filename -- in a ``.h5`` inside a quarter-width column. Long unbroken tokens
   do not wrap by default, so they overflowed the tile instead of wrapping.
3. The page was built out of raw Bootstrap ``.card`` / ``.badge bg-*`` /
   ``.alert-*``. ``.card`` has NO product override in ``fortiweb.css``, so this
   page rendered with different corners, borders and header padding from every
   other page, and the Bootstrap badge palette is not the one calibrated against
   white (``.fw-badge-*``).

A page that renders is not a page that reads: every guard here is about the
*appearance being true*, which has no exit code of its own.
"""
from __future__ import annotations

import io
import os
import re

import pytest

from app.models import Appliance, db
from tests.conftest import admin_user_id, login

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CSS_PATH = os.path.join(REPO, "app", "static", "css", "fortiweb.css")
TPL_PATH = os.path.join(REPO, "app", "templates", "appliances", "upgrade_prep.html")


@pytest.fixture(scope="module")
def css():
    return io.open(CSS_PATH, encoding="utf-8").read()


@pytest.fixture(scope="module")
def tpl():
    return io.open(TPL_PATH, encoding="utf-8").read()


def _block(css_text, selector):
    """The declaration block of ``selector`` (first definition)."""
    m = re.search(re.escape(selector) + r"\s*\{([^}]*)\}", css_text)
    assert m, "selector %s is gone from fortiweb.css" % selector
    return m.group(1)


# ------------------------------------------------- 1. the CLI output panel ---

def test_console_panel_is_not_a_dark_theme_leftover(css):
    """The exact values that made the output invisible must not come back."""
    body = _block(css, ".fw-pre")
    for dark in ("rgba(0,0,0,0.3)", "rgba(0,0,0,.3)", "#94a3b8",
                 "rgba(148,163,184,0.15)", "#cbd5e1", "#93c5fd"):
        assert dark not in body, "dark-theme value %s is back in .fw-pre" % dark


def test_console_panel_paints_from_the_light_token_set(css):
    """Tokens, not literals: the panel has to follow the product palette."""
    body = _block(css, ".fw-pre")
    assert "background: var(--fw-surface-alt)" in body
    assert "color: var(--fw-text-primary)" in body
    assert "border: 1px solid var(--fw-border)" in body


def test_console_panel_contains_its_own_overflow(css):
    """A long CLI line must scroll INSIDE the box, never widen the card.

    ``pre`` (not ``pre-wrap``) because device output is column-aligned and
    wrapping shreds the columns; the scroll is what keeps it contained.
    """
    body = _block(css, ".fw-pre")
    assert "white-space: pre;" in body
    assert re.search(r"overflow:\s*auto", body)
    assert "max-height" in body


# ------------------------------------------------------ 2. the value tiles ---

def test_fact_tile_values_wrap_instead_of_overflowing(css):
    """This is the reported symptom: a backup filename ran past the tile."""
    body = _block(css, ".fw-fact-value")
    assert "overflow-wrap: anywhere" in body
    assert "word-break: break-word" in body
    # A device string is not a headline number: .fw-stat-value's 28px is what
    # made these tiles overflow in the first place.
    size = re.search(r"font-size:\s*(\d+(?:\.\d+)?)px", body)
    assert size and float(size.group(1)) <= 16, "fact values are headline-sized again"


def test_fact_tile_can_shrink_inside_its_grid_column(css):
    """Without min-width:0 a grid/flex child refuses to shrink below content."""
    assert "min-width: 0" in _block(css, ".fw-fact")


def test_page_does_not_size_device_strings_as_headings(tpl):
    """``class="h5"`` on a firmware build is how the overflow was introduced."""
    assert 'class="h5' not in tpl
    assert "fw-fact-value" in tpl


def test_backup_filename_is_evidence_not_a_lozenge(css, tpl):
    """A 50-character filename inside a pill wraps into a two-line lozenge.

    The badge carries the VERDICT; the filename is evidence and gets its own
    breakable mono sub-line.
    """
    body = _block(css, ".fw-fact-sub")
    assert "overflow-wrap: anywhere" in body
    assert "font-family: Menlo" in body
    assert "fw-fact-sub" in tpl
    assert re.search(r"esc\(\s*bk\.name", tpl), "backup filename reaches innerHTML unescaped"
    # the whole filename must not be the badge label again
    assert "pill(d.backup.ok" not in tpl


def test_table_cells_holding_device_strings_can_break(css, tpl):
    """A published URL is long and unbroken; untreated it widens the table."""
    assert "overflow-wrap: anywhere" in _block(css, ".fw-cell-break")
    assert "fw-cell-break" in tpl


# ------------------------------------------------------------- 3. the chrome ---

def test_page_uses_the_product_card_not_the_bootstrap_one(tpl):
    """``.card`` has no override in fortiweb.css -- it renders unlike every
    other page in the product."""
    assert "fw-card" in tpl
    assert not re.search(r'class="card\b', tpl)
    assert not re.search(r'class="card-body\b', tpl)
    assert not re.search(r'class="card-header\b', tpl)


def test_page_uses_the_calibrated_badge_and_alert_palettes(tpl):
    """``.fw-badge-*`` / ``.fw-alert-*`` are the sets calibrated against white."""
    assert "fw-badge fw-badge-" in tpl
    assert "fw-alert-success" in tpl and "fw-alert-warning" in tpl
    assert "badge bg-" not in tpl
    # (?<!fw-) or this matches inside the CORRECT class name: the ninth
    # substring assertion in this repo to match its own right answer.
    assert not re.search(r"(?<!fw-)\balert-(success|warning|danger|secondary)\b", tpl)
    # text-success/text-danger on white is 3.1:1 / 3.9:1 -- below AA for the
    # 12px status text this page renders it at.
    assert "text-success" not in tpl
    assert "text-danger" not in tpl


# --------------------------------------------- device data is never markup ---

def test_device_supplied_values_are_escaped_before_innerhtml(tpl):
    """A policy name carrying '<' silently ate the rest of the row: a layout
    defect that looks exactly like missing data."""
    assert "function esc(" in tpl
    for field in ("t.policy", "t.url", "r.reason", "j.prep_summary", "t.note"):
        assert re.search(r"esc\(\s*" + re.escape(field), tpl), \
            "%s reaches innerHTML unescaped" % field
    # the raw interpolations that were there before must not return
    assert "${t.policy}" not in tpl
    assert "${t.url}" not in tpl


# ------------------------------------------------------- rendered output ---

def test_prep_page_renders_the_light_chrome(app, client):
    """The markup has to survive Jinja, not merely exist in the template."""
    with app.app_context():
        a = Appliance(name="prepbox", host="192.0.2.99", port=443, kind="fortiweb",
                      username="admin")
        a.password = "pw"
        db.session.add(a)
        db.session.commit()
        aid = a.id

    login(client, admin_user_id(app))
    r = client.get("/appliances/%d/upgrade/prep" % aid)
    assert r.status_code == 200
    html = r.get_data(as_text=True)
    assert "fw-fact-value" in html
    assert 'class="fw-pre"' in html
    # Scope the sweep to THIS page's block. base.html's sidebar legitimately
    # paints slate icons on the dark-blue rail; scanning the whole document
    # would fail against correct chrome -- the same over-broad-scan trap that
    # flagged the CHANGELOG page during the brand-mark round.
    body = html[html.index("fw-page-header"):]
    for dark in ("rgba(30,41,59,", "rgba(15,23,42,", "rgba(0,0,0,0.3)",
                 "backdrop-filter", "#94a3b8", "#cbd5e1"):
        assert dark not in body, "dark-theme value %s leaked into the page" % dark


# =========================================================================== #
#  Reading BACK a recorded run (2026-08-10)                                    #
# =========================================================================== #
# The runs were already stored, listed and citable -- and not readable. The
# table said "passed, 12 services"; the health battery, the backup filename and
# the per-policy baseline that produced that verdict were in the row with no way
# out. None of that raises either: the page rendered, the row rendered, the
# count was right. What was missing had no failure mode of its own.

RESULT_FIXTURE = {
    "firmware": "FortiWeb-VM 7.6.8,build1234",
    "permission": True,
    "backup": {"ok": True, "name": "prepbox-20260810-004500.conf"},
    "health": {"ok": True, "text": "CPU 4%   MEM 51%\nHA  standalone"},
    "services": {"ok": True, "probes": [
        {"target": {"policy": "www_prod", "url": "https://shop.example.com/",
                    "backends": ["192.0.2.5:443"], "note": ""},
         "result": {"ok": True, "status": 200, "elapsed_ms": 41}},
    ]},
}
INVENTORY_FIXTURE = [
    {"device": "prepbox", "policy": "www_prod", "vserver": "vs_ext",
     "service": "HTTPS", "status": "enable", "url": "https://shop.example.com/",
     "probe_ok": True, "http_status": 200},
    # never probed -- the third state that must not read like a failure
    {"device": "prepbox", "policy": "api_prod", "vserver": "vs_ext",
     "service": "HTTPS", "status": "enable", "url": "",
     "probe_ok": "", "http_status": ""},
]


def _appliance_with_prep(app, *, ok=True):
    """An appliance plus one recorded run. Returns ``(appliance_id, prep_id)``."""
    import json as _json

    from app.models import UpgradePrep
    with app.app_context():
        a = Appliance(name="prepbox2", host="192.0.2.98", port=443,
                      kind="fortiweb", username="admin")
        a.password = "pw"
        db.session.add(a)
        db.session.commit()
        prep = UpgradePrep(
            appliance_id=a.id, created_by="operator", ok=ok,
            firmware=RESULT_FIXTURE["firmware"],
            summary="backup ok, health ok, services 1/1 reachable",
            result=_json.dumps(RESULT_FIXTURE),
            inventory=_json.dumps(INVENTORY_FIXTURE))
        db.session.add(prep)
        db.session.commit()
        return a.id, prep.id


def test_recorded_run_can_be_opened_at_all(app, client):
    """The whole point: the stored evidence has a way out of the row."""
    aid, pid = _appliance_with_prep(app)
    login(client, admin_user_id(app))
    r = client.get("/appliances/%d/upgrade/prep/%d.json" % (aid, pid))
    assert r.status_code == 200, "recorded runs are unreadable again"
    j = r.get_json()
    assert j["ok"] is True
    # The parts that were trapped in the row, not just the verdict:
    assert j["result"]["health"]["text"].startswith("CPU 4%")
    assert j["result"]["backup"]["name"] == "prepbox-20260810-004500.conf"
    assert j["result"]["services"]["probes"][0]["target"]["policy"] == "www_prod"
    assert len(j["inventory"]) == 2


def test_recorded_run_announces_that_it_is_recorded(app, client):
    """Same panel, same renderer -- so the payload has to carry the label.

    A two-day-old health battery looks exactly like one taken thirty seconds
    ago. Without ``stored`` there is nothing on screen to tell them apart.
    """
    aid, pid = _appliance_with_prep(app)
    login(client, admin_user_id(app))
    j = client.get("/appliances/%d/upgrade/prep/%d.json" % (aid, pid)).get_json()
    assert j["stored"] is True
    assert j["created_at"], "a recorded run with no timestamp cannot be dated"
    assert j["created_by"] == "operator"


def test_a_prep_from_another_appliance_is_not_served_here(app, client):
    """The appliance is part of the lookup key, not decoration.

    A pre-flight rendered under the wrong device's heading is worse than no
    pre-flight: it is evidence about a box nobody checked.
    """
    aid_a, pid_a = _appliance_with_prep(app)
    with app.app_context():
        b = Appliance(name="otherbox", host="192.0.2.97", port=443,
                      kind="fortiweb", username="admin")
        b.password = "pw"
        db.session.add(b)
        db.session.commit()
        bid = b.id
    login(client, admin_user_id(app))
    r = client.get("/appliances/%d/upgrade/prep/%d.json" % (bid, pid_a))
    assert r.status_code == 404
    assert r.get_json()["ok"] is False


def test_recorded_run_is_not_public(app, client):
    """No session, no evidence."""
    aid, pid = _appliance_with_prep(app)
    r = client.get("/appliances/%d/upgrade/prep/%d.json" % (aid, pid))
    assert r.status_code in (302, 401, 403), "recorded pre-flights are public"


def test_recorded_run_requires_the_same_permission_as_running_one(app, client):
    """Reading the evidence back is not a lesser act than producing it.

    Asserting "an anonymous caller is refused" proves ``login_required`` and
    NOTHING about the permission -- it passed with ``@require_permission``
    deleted. The mutation caught it. A logged-in READONLY user is the only
    caller that separates the two gates.
    """
    from tests.conftest import make_user
    aid, pid = _appliance_with_prep(app)
    login(client, make_user(app, username="ro_prep", role="readonly"))
    r = client.get("/appliances/%d/upgrade/prep/%d.json" % (aid, pid))
    assert r.status_code in (302, 401, 403), \
        "a readonly account can read pre-flight evidence (permission gate gone)"


def test_live_and_recorded_runs_share_one_renderer(tpl):
    """Two renderers for one payload drift silently -- BOTH still paint.

    The live path must not keep a private copy of the painting code: that is
    exactly how two descriptions of one fact end up disagreeing with nothing to
    say which is true.
    """
    assert "function paint(j)" in tpl
    # both entry points end in paint()
    assert tpl.count("paint(j);") >= 2
    # the old inline copy in the run handler must not come back
    run_block = tpl[tpl.index("btn.addEventListener"):]
    for owned in ("r-fw').textContent", "r-health').textContent = (d.health",
                  "svcTable(probes)"):
        assert owned not in run_block, \
            "the run handler paints its own copy again: %s" % owned


def test_the_three_probe_states_do_not_collapse(tpl):
    """'' never probed, false probed-and-failed, true reachable.

    Collapsing unknown into down invents an outage; collapsing it into up hides
    one. ``prep_store.build_inventory`` writes all three on purpose.
    """
    assert "not probed" in tpl
    assert re.search(r"r\.probe_ok\s*===\s*''", tpl), \
        "the 'never probed' state is gone -- unknown now reads as a verdict"
    assert "unreachable" in tpl


def test_recorded_inventory_values_are_escaped_before_innerhtml(tpl):
    """Frozen rows are still device data: a policy name with '<' eats the row."""
    for field in ("r.policy", "r.url", "r.vserver", "r.service"):
        assert re.search(r"esc\(\s*" + re.escape(field), tpl), \
            "%s reaches innerHTML unescaped" % field


def test_the_runs_table_does_not_silently_omit(tpl):
    """It shows ten. A capped list that looks complete is a false statement,
    and a fresh run does not appear in a server-rendered table until reload."""
    assert "10 most recent" in tpl
    assert "prep-runs-stale" in tpl


def test_inventory_columns_are_named_by_the_export_catalog(app, client, tpl):
    """One column, one name.

    The same rows leave this product twice — on screen and as the CSV/XLSX a
    change request is signed against. Hand-typed headings give one column two
    names, and the operator comparing the two has nothing to tell him which
    sheet the approval covers.
    """
    from app.services import prep_store
    aid, pid = _appliance_with_prep(app)
    login(client, admin_user_id(app))
    j = client.get("/appliances/%d/upgrade/prep/%d.json" % (aid, pid)).get_json()
    catalog = {f["key"]: f["label"] for f in j["inventory_fields"]}
    assert catalog == dict(prep_store.FIELDS), \
        "the page is served a different field catalog than the exports use"
    assert "label[k]" in tpl, "the headings are hand-typed again"
    for hardcoded in ("<th>Policy / virtual server</th>", "<th>Admin status</th>"):
        assert hardcoded not in tpl


def test_each_recorded_row_offers_its_result(tpl):
    """A row that can only be cited, never opened, is a receipt."""
    assert 'class="btn btn-sm fw-btn-secondary prep-view"' in tpl
    assert 'data-prep="{{ r.id }}"' in tpl
    assert "upgrade_prep_show" in tpl
