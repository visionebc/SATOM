"""The published border blocklist — the list, the feed, the mirror, the release.

What is actually at risk here
-----------------------------
This is the first response path in the product whose enforcement point is
**outside** it. Every guard below exists because one specific thing can go
wrong and would not announce itself:

* **The TTL stops being a property of the appliance.** ``block_ip`` on
  FortiWeb uses ``action=block-period``: the device expires the block on its
  own and that expiry survives Sentinel being dead. A feed has no such timer.
  The design answer is that the endpoint renders FROM THE DATABASE on every
  request and filters by ``expires_at`` — so a stopped publisher cannot serve
  an expired address. If anything ever inserts a cached file into that path,
  every entry becomes permanent the moment the job stops, silently.

* **The wrong address ends up on the list.** FortiWeb reports the true client
  when a policy reads ``X-Forwarded-For`` and the CDN's own address when it
  does not, and nothing in the attack log distinguishes them. Listing the
  second kind removes every legitimate client behind a shared egress. The
  border veto is the only thing that separates them and it must fail closed.

* **The feed leaks.** It answers without a login, because a firewall cannot
  log in. The token is the entire authentication, and an UNSET token must
  match nothing — ``compare_digest("", "")`` is True, so a naive comparison
  would serve the fleet's blocklist to any anonymous request that also omitted
  the parameter.

* **The audit mirror publishes operational data.** SATOM's own repository is
  mirrored to a public host by the release tooling. A blocklist committed
  there would disclose which addresses attacked which customer. Nothing may
  default the mirror at the code repository.

* **The never-block list becomes unreadable.** An unparseable ``protect_cidrs``
  line makes the protection policy unevaluable, and the permissive reading of
  a broken protection list is "protect nothing". This refuses instead, the
  same way the access gate answers 503 rather than serving.

What this file deliberately does NOT test
-----------------------------------------
Whether a FortiGate consumes the feed. No firewall in this fleet has been
pointed at it, so that half ships unverified and says so in the catalog
provenance. Asserting the behaviour of a device nobody has run this against
would freeze a guess.
"""
from __future__ import annotations

import io
import re
from datetime import datetime, timedelta

import pytest
from conftest import admin_user_id, login

from app.models import db
from app.models_sentinel import SentinelBlockEntry
from app.services.sentinel import actions as sn_actions
from app.services.sentinel import blocklist, config as sn_config

SECTION = "app/templates/sentinel/_blocklist_section.html"
PANE = "app/templates/settings/index.html"
NAV = "app/templates/settings/_nav.html"
SRC = "app/services/sentinel/blocklist.py"
VIEWS = "app/views/sentinel.py"

#: Genuinely globally-routable addresses. The documentation ranges
#: (192.0.2/24, 198.51.100/24, 203.0.113/24) live inside ipaddress's private
#: set, so ``is_global`` refuses them on its own -- using them as fixtures
#: made every listing test fail for a reason unrelated to what it checked,
#: which is a fixture that lies rather than a guard that works.
PUB = "45.33.32.156"
PUB2 = "104.18.5.1"
CEIL = {1: "23.20.0.1", 2: "34.200.0.2", 3: "52.10.0.3"}

FEED_KEYS = ("feed_enabled", "feed_token", "feed_ttl_hours",
             "feed_max_entries", "feed_stale_minutes", "feed_git_remote",
             "feed_git_branch", "feed_git_token", "feed_git_auto")

#: A border result that PASSES the veto, as a plain literal — see the same
#: note in test_sentinel_edge.py: ``edge.blank()`` reads a setting, so it
#: cannot be called at collection time.
GOOD_EDGE = {
    "enabled": True, "mapped": True, "checked": True, "corroborated": True,
    "verdict": "corroborated", "multi_target": False, "reason": "", "error": "",
    "scope": "faz01 · adom root · device fgt01 · vdom customer-a",
    "hits": 7, "distinct_dst": 3, "distinct_dport": 2, "denied": 0, "rows": [],
}


def _read(path: str) -> str:
    return io.open(path, encoding="utf-8").read()


def _uncommented(text: str) -> str:
    """Strip Jinja / HTML / Python comments before asserting on source.

    Eleventh recurrence in this repo: a guard whose expectation appears
    verbatim in the prose that EXPLAINS the guard passes against code that no
    longer satisfies it. Every docstring above names the thing it guards.
    """
    text = re.sub(r"\{#.*?#\}", "", text, flags=re.S)
    text = re.sub(r"<!--.*?-->", "", text, flags=re.S)
    text = re.sub(r'"""(?:.|\n)*?"""', "", text)
    text = re.sub(r"^\s*#.*$", "", text, flags=re.M)
    return text


@pytest.fixture()
def armed(app):
    """A context where listing is possible: token set, feed on, no protect."""
    with app.app_context():
        sn_config.set_value("feed_enabled", True)
        sn_config.set_value("edge_require", True)
        sn_config.set_value("protect_cidrs", "10.0.0.0/8\n8.8.8.0/24")
        blocklist.rotate_token()
        yield


# --------------------------------------------------------------------------- #
#  Address policy — what may never be listed, and WHY not                       #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("value,fragment", [
    ("not-an-ip", "does not parse"),
    ("8.8.8.8", "protected network"),
    ("192.168.5.5", "public unicast"),
    ("127.0.0.1", "loopback"),
    ("224.0.0.1", "multicast"),
    ("240.0.0.1", "reserved"),
    ("169.254.1.1", "link-local"),
    ("0.0.0.0", "unspecified"),
])
def test_every_refusal_says_which_rule_refused_it(armed, app, value, fragment):
    """A shared boolean would collapse four different operator actions.

    "the address does not parse" means somebody typed it wrong. "inside a
    protected network" means somebody tried to block their own monitoring.
    "not a public unicast address" means the correlation read the wrong field
    off the log. They are not interchangeable and a caller that only learns
    ``False`` cannot tell an operator which one happened.
    """
    with app.app_context():
        why = blocklist.not_listable(blocklist.parse(value))
    assert why, f"{value} was accepted"
    assert fragment in why, why


def test_an_unreadable_never_block_list_stops_everything(app):
    """The permissive reading of a broken protection list is 'protect nothing'.

    That is exactly backwards and it is silent: the bad line is dropped by
    ``protected_networks()`` and every other address sails through. The same
    argument the access gate makes when it answers 503 instead of serving.
    """
    with app.app_context():
        sn_config.set_value("protect_cidrs", "10.0.0.0/8\nnot-a-cidr")
        why = blocklist.not_listable(blocklist.parse(PUB))
    assert why, "a perfectly public address was accepted with a broken " \
                "never-block list"
    assert "unparseable" in why and "protect_cidrs" in why, why


def test_a_public_address_is_listable_when_the_policy_is_readable(armed, app):
    """The negative control. Without it every guard above passes on a
    function that refuses everything."""
    with app.app_context():
        assert blocklist.not_listable(blocklist.parse(PUB)) == ""


def test_a_prefix_is_not_an_address(app):
    """CIDR is refused at the parser. A ``/24`` is 256 customers and nothing
    in this pipeline produces evidence about a network."""
    with app.app_context():
        assert blocklist.parse("45.33.0.0/16") is None


# --------------------------------------------------------------------------- #
#  The veto                                                                     #
# --------------------------------------------------------------------------- #
def test_listing_without_border_corroboration_is_refused(armed, app):
    with app.app_context():
        out = blocklist.add(PUB, reason="t", actor="tester", edge={})
    assert not out["ok"]
    assert out["overridable"] is True
    assert blocklist.parse(PUB) is not None


def test_listing_with_corroboration_creates_a_live_entry(armed, app):
    with app.app_context():
        out = blocklist.add(PUB, hours=6, reason="sqli burst",
                            actor="tester", edge=GOOD_EDGE)
        assert out["ok"], out
        entry = out["entry"]
        assert entry.live
        assert entry.edge_verdict == "corroborated"
        assert entry.edge_hits == 7
        assert entry.expires_at > datetime.utcnow()
        assert entry.override_by == ""


def test_an_override_needs_a_written_reason(armed, app):
    """An override with no reason is an override nobody can review."""
    with app.app_context():
        bad = blocklist.add(PUB, actor="tester", edge={},
                            override=True)
        assert not bad["ok"], bad
        assert "written reason" in bad["reason"]
        good = blocklist.add(PUB, actor="tester", edge={},
                             override=True,
                             override_reason="confirmed with the customer")
        assert good["ok"], good
        assert good["entry"].override_by == "tester"
        assert "customer" in good["entry"].override_reason


def test_the_protected_network_guard_survives_an_override(armed, app):
    """The escape hatch relaxes the BORDER veto, never the never-block list.

    They answer different questions. The border veto is about whether an
    address is a real peer — a judgement an operator may legitimately make
    differently. A protected CIDR is our own infrastructure and there is no
    judgement available.
    """
    with app.app_context():
        out = blocklist.add("8.8.8.8", actor="tester", edge={}, override=True,
                            override_reason="I really mean it")
    assert not out["ok"]
    assert "protected network" in out["reason"]


# --------------------------------------------------------------------------- #
#  TTL — the property this whole design is bent around                          #
# --------------------------------------------------------------------------- #
def test_no_entry_can_exist_without_an_expiry(armed, app):
    with app.app_context():
        out = blocklist.add(PUB, hours=0, actor="t", edge=GOOD_EDGE)
        assert out["entry"].expires_at is not None
    assert SentinelBlockEntry.expires_at.nullable is False, (
        "expires_at became nullable — the database would then permit an entry "
        "with no expiry at all, and the feed would serve it forever")


def test_the_ttl_ceiling_is_enforced_in_code_not_in_the_form(armed, app):
    with app.app_context():
        out = blocklist.add(PUB, hours=99999, actor="t",
                            edge=GOOD_EDGE)
        span = out["entry"].expires_at - out["entry"].created_at
    assert span <= timedelta(hours=blocklist.MAX_TTL_HOURS + 1), span


def test_an_expired_entry_is_never_served_even_if_nothing_expired_it(armed, app):
    """THE guard for the property that replaces the appliance-side timer.

    ``expire_due`` is bookkeeping. If :func:`live_entries` ever trusts
    ``status`` instead of reading ``expires_at``, then a scheduler that stops
    turns every block permanent — and the page would still say ``active``, so
    nothing would look wrong.
    """
    with app.app_context():
        out = blocklist.add(PUB, hours=1, actor="t", edge=GOOD_EDGE)
        row = out["entry"]
        row.expires_at = datetime.utcnow() - timedelta(minutes=1)
        db.session.commit()
        assert row.status == SentinelBlockEntry.ACTIVE, \
            "the fixture failed to reproduce 'expiry passed, nothing ran'"
        assert blocklist.live_entries() == []
        assert PUB not in blocklist.render()


def test_expire_due_flips_the_row_and_is_idempotent(armed, app):
    with app.app_context():
        out = blocklist.add(PUB, hours=1, actor="t", edge=GOOD_EDGE)
        out["entry"].expires_at = datetime.utcnow() - timedelta(minutes=1)
        db.session.commit()
        assert len(blocklist.expire_due()) == 1
        assert out["entry"].status == SentinelBlockEntry.EXPIRED
        assert blocklist.expire_due() == []


def test_a_second_listing_extends_but_never_shortens(armed, app):
    """A fresh burst arriving with the default TTL must not cut short a longer
    block an operator set deliberately."""
    with app.app_context():
        first = blocklist.add(PUB, hours=48, actor="op",
                              edge=GOOD_EDGE)["entry"]
        far = first.expires_at
        again = blocklist.add(PUB, hours=1, actor="system",
                              source="incident", edge=GOOD_EDGE)
        assert again["ok"] and again["entry"].id == first.id
        assert again["entry"].expires_at == far, "a longer block was shortened"
        longer = blocklist.add(PUB, hours=200, actor="op",
                               edge=GOOD_EDGE)
        assert longer["entry"].expires_at > far
        assert SentinelBlockEntry.query.count() == 1, "a duplicate row was made"


def test_a_lapsed_entry_is_re_listed_fresh_not_revived(armed, app):
    """An expired row that nothing has flipped yet is still ``active``.

    Extending it would revive a lapsed block while keeping the ORIGINAL
    created_at, created_by and border verdict — so a new listing would be
    documented by evidence gathered for a previous one. The audit trail is the
    whole point of keeping these rows.
    """
    with app.app_context():
        old = blocklist.add(PUB, hours=1, actor="alice", edge=GOOD_EDGE)["entry"]
        old.expires_at = datetime.utcnow() - timedelta(minutes=1)
        db.session.commit()
        assert old.status == SentinelBlockEntry.ACTIVE, \
            "the fixture failed to reproduce 'expired, nothing flipped it'"
        again = blocklist.add(PUB, hours=4, actor="bob", edge=GOOD_EDGE)
        assert again["ok"] and again["status"] == blocklist.OK
        assert again["entry"].id != old.id, "a lapsed block was revived"
        assert again["entry"].created_by == "bob"
        assert [e.id for e in blocklist.live_entries()] == [again["entry"].id]


# --------------------------------------------------------------------------- #
#  Capacity                                                                     #
# --------------------------------------------------------------------------- #
def test_at_the_ceiling_a_new_entry_is_refused_and_nothing_is_evicted(armed, app):
    """Evicting the oldest live row silently unblocks an address that is still
    inside its TTL, and the only telemetry would be traffic resuming."""
    with app.app_context():
        sn_config.set_value("feed_max_entries", 2)
        for i in (1, 2):
            assert blocklist.add(CEIL[i], actor="t",
                                 edge=GOOD_EDGE)["ok"]
        out = blocklist.add(CEIL[3], actor="t", edge=GOOD_EDGE)
        assert not out["ok"]
        assert "ceiling" in out["reason"]
        live = {e.ip for e in blocklist.live_entries()}
        assert live == {CEIL[1], CEIL[2]}, \
            "an entry inside its TTL was evicted to make room"


# --------------------------------------------------------------------------- #
#  Release                                                                      #
# --------------------------------------------------------------------------- #
def test_release_takes_it_off_the_feed_and_keeps_the_record(armed, app):
    with app.app_context():
        row = blocklist.add(PUB, actor="t", edge=GOOD_EDGE)["entry"]
        out = blocklist.release(row.id, actor="alice", reason="false positive")
        assert out["ok"], out
        assert PUB not in blocklist.render()
        kept = SentinelBlockEntry.query.get(row.id)
        assert kept is not None, "the row was deleted — the release history " \
                                 "is the only evidence of how often this " \
                                 "list is wrong"
        assert kept.status == SentinelBlockEntry.RELEASED
        assert kept.released_by == "alice"
        assert "false positive" in kept.release_reason


def test_releasing_twice_is_refused_rather_than_silently_repeated(armed, app):
    with app.app_context():
        row = blocklist.add(PUB, actor="t", edge=GOOD_EDGE)["entry"]
        assert blocklist.release(row.id, actor="a")["ok"]
        second = blocklist.release(row.id, actor="b")
        assert not second["ok"]
        assert SentinelBlockEntry.query.get(row.id).released_by == "a"


def test_deleting_an_incident_must_not_unblock_its_address(app):
    """``SET NULL``, not cascade. The block outlives the record of why it was
    made; losing the reason is a documentation problem, losing the block is a
    security one."""
    fk = SentinelBlockEntry.__table__.c.incident_id.foreign_keys
    assert fk, "incident_id lost its foreign key"
    assert all(f.ondelete == "SET NULL" for f in fk), \
        "incident_id cascades — deleting an old incident would silently " \
        "unblock an address that is still inside its TTL"


# --------------------------------------------------------------------------- #
#  Render                                                                       #
# --------------------------------------------------------------------------- #
def test_the_render_stamps_generated_at_and_stale_after(armed, app):
    """A consumer holding a cached copy cannot otherwise tell a current list
    from a frozen one, and a frozen list is a permanent block."""
    with app.app_context():
        body = blocklist.render()
    assert "# generated_at:" in body
    assert "# stale_after:" in body
    assert "# entries:" in body


def test_the_body_is_one_bare_address_per_line(armed, app):
    """A threat feed is consumed by a machine. Anything but the address on a
    non-comment line is a line the connector rejects or, worse, misreads."""
    with app.app_context():
        blocklist.add(PUB, actor="t", edge=GOOD_EDGE)
        blocklist.add(PUB2, actor="t", edge=GOOD_EDGE)
        body = blocklist.render()
    payload = [l for l in body.splitlines() if l and not l.startswith("#")]
    assert sorted(payload) == [PUB2, PUB], payload


# --------------------------------------------------------------------------- #
#  The token and the endpoint                                                   #
# --------------------------------------------------------------------------- #
def test_an_unset_token_matches_nothing_including_the_empty_string(app):
    """``secrets.compare_digest("", "")`` is True. Without the emptiness check
    an installation that never configured a token would serve the fleet's
    blocklist to any anonymous request that also omitted it."""
    with app.app_context():
        sn_config.set_value("feed_token", "")
        assert blocklist.token_matches("") is False
        assert blocklist.token_matches("anything") is False


def test_the_feed_serves_the_live_list_without_a_login(armed, app, client):
    with app.app_context():
        blocklist.add(PUB, actor="t", edge=GOOD_EDGE)
        token = blocklist.current_token()
    res = client.get(f"/sentinel/feed/{token}/blocklist.txt")
    assert res.status_code == 200, "a firewall cannot log in"
    assert PUB.encode() in res.data
    assert res.mimetype == "text/plain"
    assert "no-store" in res.headers.get("Cache-Control", ""), \
        "a cached blocklist outlives its entries' TTLs"


def test_a_wrong_token_is_indistinguishable_from_no_such_feed(armed, app,
                                                              client):
    assert client.get("/sentinel/feed/wrong/blocklist.txt").status_code == 404


def test_the_feed_is_404_while_the_switch_is_off(armed, app, client):
    with app.app_context():
        sn_config.set_value("feed_enabled", False)
        token = blocklist.current_token()
    assert client.get(
        f"/sentinel/feed/{token}/blocklist.txt").status_code == 404


def test_a_released_address_leaves_the_feed_on_the_next_fetch(armed, app,
                                                             client):
    with app.app_context():
        row = blocklist.add(PUB, actor="t", edge=GOOD_EDGE)["entry"]
        token = blocklist.current_token()
        eid = row.id
    assert PUB.encode() in client.get(
        f"/sentinel/feed/{token}/blocklist.txt").data
    with app.app_context():
        blocklist.release(eid, actor="t", reason="fp")
    assert PUB.encode() not in client.get(
        f"/sentinel/feed/{token}/blocklist.txt").data


def test_rotating_the_token_revokes_the_old_url_immediately(armed, app, client):
    """No grace period and no second valid token: a rotation that keeps the
    old one working has revoked nothing."""
    with app.app_context():
        old = blocklist.current_token()
        new = blocklist.rotate_token()
    assert old != new
    assert client.get(f"/sentinel/feed/{old}/blocklist.txt").status_code == 404
    assert client.get(f"/sentinel/feed/{new}/blocklist.txt").status_code == 200


def test_the_serving_path_never_reads_a_file(app):
    """The property that replaces the appliance-side timer, asserted against
    the source: if a cached artefact ever enters this route, every entry
    becomes permanent the moment the publisher stops."""
    src = _uncommented(_read(VIEWS))
    route = re.search(r"def blocklist_feed\(token\):(.*?)\ndef ", src, re.S)
    assert route, "the feed route disappeared"
    body = route.group(1)
    assert ".render()" in body, "the feed stopped rendering from the database"
    for forbidden in ("open(", "read_text", "MIRROR_FILE", "send_file"):
        assert forbidden not in body, (
            f"the feed route reads {forbidden!r} — a cached blocklist in the "
            f"serving path cannot expire")


# --------------------------------------------------------------------------- #
#  The audit mirror                                                             #
# --------------------------------------------------------------------------- #
def test_the_mirror_is_off_and_unpointed_by_default(app):
    """A default remote is how operational data escapes."""
    with app.app_context():
        assert sn_config.get("feed_git_remote") == ""
        assert sn_config.get("feed_git_auto") is False


def test_the_mirror_never_defaults_at_this_products_own_repository(app):
    """SATOM's source repo is mirrored to a public host by the release
    tooling. A blocklist committed there discloses which addresses attacked
    which customer."""
    # _uncommented FIRST: the prose that explains this guard has to name the
    # repository it forbids, so a raw substring check matches its own comment
    # and passes against code that hard-codes the very thing it bans. Tenth
    # recurrence of that defect in this repo.
    src = _uncommented(_read(SRC))
    assert "satom-dev/satom" not in src
    assert not blocklist.MIRROR_DIR.startswith("/opt/satom/"), \
        f"the mirror working copy is inside the source tree ({blocklist.MIRROR_DIR})"
    assert "/data/" not in blocklist.MIRROR_DIR, \
        "the standby's rsync --delete datasync would wipe a git working tree"


def test_a_mirror_that_cannot_run_never_blocks_a_listing(armed, app):
    """The mirror is the audit copy; the feed is the enforcement path."""
    with app.app_context():
        sn_config.set_value("feed_git_remote", "https://nowhere.invalid/x.git")
        sn_config.set_value("feed_git_auto", True)
        assert blocklist.add(PUB, actor="t", edge=GOOD_EDGE)["ok"]
        out = blocklist.publish(actor="t")
        assert out["entries"] == 1
        assert out["mirrored"] is False


def test_the_mirror_credential_is_redacted_from_everything_returned(app):
    """TWO layers, asserted SEPARATELY — and that separation is the point.

    A single sample containing a credential inside a URL is scrubbed by the
    pattern alone, so deleting the token replacement changed nothing
    observable and the mutation survived. Both layers are genuinely needed and
    they cover different cases, so each gets a sample only it can handle.
    (Found by mutation, 2026-08-23.)
    """
    with app.app_context():
        # Layer 1 — the known token, wherever it appears. git does not only
        # echo credentials inside URLs.
        bare = blocklist._redact("remote: bad credentials for s3cr3t", "s3cr3t")
        assert "s3cr3t" not in bare, \
            "a token outside a URL survived — only the pattern ran"
        assert "***" in bare
        # Layer 2 — a credential embedded in a URL, WITHOUT being told what it
        # is. The operator may type a remote that already carries one.
        url = blocklist._redact("fatal: https://satom:hunter2@git.example/x.git")
        assert "hunter2" not in url, \
            "an embedded credential survived — only the token replacement ran"
        assert "***:***@" in url


# --------------------------------------------------------------------------- #
#  The action catalog                                                           #
# --------------------------------------------------------------------------- #
def test_block_edge_ip_is_capped_at_recommend_forever(app):
    """Its blast radius is every FortiGate and VDOM reading the feed, so every
    service behind them — wider than any FortiWeb action in this product. A
    verified mechanism would not be an argument for autonomy here either."""
    from app.models_sentinel import SentinelPolicy
    spec = sn_actions.CATALOG["block_edge_ip"]
    assert spec.max_level == SentinelPolicy.LEVEL_RECOMMEND
    assert spec.requires_ttl is True
    assert spec.reversible is True
    assert spec.verified is False, \
        "no FortiGate in this fleet has been pointed at the feed"
    assert spec.handoff is True, \
        "there is no device write here, so the runner must refuse it by name " \
        "rather than look for a transport that cannot exist"


def test_no_transport_exists_for_the_border_action(app):
    """The whole point of the feed: SATOM never writes to a FortiGate."""
    from app.services.sentinel import transports
    assert transports.get("block_edge_ip") is None


def test_the_catalog_entry_names_the_wider_blast_radius(app):
    blast = sn_actions.CATALOG["block_edge_ip"].blast.lower()
    assert "every" in blast
    assert "vdom" in blast or "fortigate" in blast


# --------------------------------------------------------------------------- #
#  Settings and the two surfaces                                                #
# --------------------------------------------------------------------------- #
def test_every_feed_setting_exists_and_carries_a_hint(app):
    keys = {s["key"] for s in sn_config.SPEC}
    for key in FEED_KEYS:
        assert key in keys, f"{key} is not in the spec"
        spec = next(s for s in sn_config.SPEC if s["key"] == key)
        assert spec["group"] == "blocklist"
        assert len(spec.get("hint", "")) > 120, f"{key} ships without a hint"
    assert "blocklist" in dict(sn_config.GROUPS)
    assert sn_config.UI_HINTS.get("group.blocklist")


def test_the_feed_is_off_by_default(app):
    """Turning Sentinel on must never be the same act as publishing a URL that
    answers without a login."""
    with app.app_context():
        assert sn_config.get("feed_enabled") is False
        assert sn_config.get("feed_token") == ""


def test_the_settings_pane_deploys_every_key_the_context_builder_returns(app):
    """The pane re-lists the constructor's keys by hand, which is a second
    copy, which drifts. The Context pane drifted exactly this way and took the
    whole Settings page down with a 500."""
    from app.views.sentinel import blocklist_context
    with app.app_context():
        keys = set(blocklist_context().keys())
    pane = _uncommented(_read(PANE))
    block = re.search(r'id="tab-sentinel-blocklist".*?\{%\s*include', pane, re.S)
    assert block, "the sentinel-blocklist pane disappeared"
    body = block.group(0)
    missing = sorted(k for k in keys
                     if not re.search(rf"\b{re.escape(k)}\s*=", body))
    assert not missing, f"the pane does not deploy {missing}"


def test_the_menu_offers_the_blocklist_entry(app):
    """Without it the page is reachable only by deep link — which is how
    Response policy ended up reachable only from a button inside a health
    tile."""
    nav = _uncommented(_read(NAV))
    assert "'tab-sentinel-blocklist'" in nav
    assert nav.count("'tab-sentinel") >= 6


def test_every_post_form_in_the_section_returns_to_the_surface_it_came_from():
    """Read from the SOURCE, not from rendered output: the entries table draws
    one Release form PER ROW, so on a fresh install a check against rendered
    HTML sees zero of them and reports a clean result."""
    body = _uncommented(_read(SECTION))
    forms = re.findall(r'<form[^>]*method="post"[^>]*>(.*?)</form>', body, re.S)
    assert len(forms) >= 4, f"only {len(forms)} POST forms scanned"
    missing = [f[:80] for f in forms if 'name="return_to"' not in f]
    assert not missing, missing


def test_both_surfaces_render_the_section(app, client):
    login(client, admin_user_id(app))
    for url in ("/sentinel/blocklist", "/settings/"):
        res = client.get(url)
        assert res.status_code == 200, (url, res.status_code)
        assert b"Border blocklist" in res.data, url


def test_the_page_states_the_property_the_feed_gives_up(app, client):
    """The regression is real and it belongs on the page, not only in the
    docs: on FortiWeb the APPLIANCE expires the block and that survives
    Sentinel being dead. A feed has no such timer."""
    body = _uncommented(_read(SECTION)).lower()
    assert "frozen" in body
    assert "expire" in body


def test_the_incident_page_offers_the_listing_and_names_the_veto(app):
    body = _uncommented(_read("app/templates/sentinel/incident.html")).lower()
    assert "incident_blocklist" in body
    assert "cdn" in body or "shared egress" in body


# --------------------------------------------------------------------------- #
#  The scheduled job                                                            #
# --------------------------------------------------------------------------- #
def test_the_publish_job_is_in_the_catalog_and_touches_no_appliance(app):
    from app.services import scheduled_actions as sa
    spec = next(s for s in sa.ADMIN_ACTIONS if s.key == "sentinel_feed_publish")
    assert spec.needs_targets is False
    assert spec.danger is False
    assert "does NOT make the feed current" in spec.summary


def test_the_publish_job_is_dispatched(app):
    """A catalog entry with no dispatch branch is an action that runs nothing
    and reports success."""
    src = _uncommented(_read("app/services/scheduled_actions.py"))
    assert 'key == "sentinel_feed_publish"' in src
    assert "_do_sentinel_feed_publish(params, dry_run)" in src
