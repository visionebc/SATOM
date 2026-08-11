"""The drift alert names who made the change, or says it searched and found nobody.

Until 2026-08-11 every drift alert ended with *"If nobody edited it via SATOM, a
device-side (CLI/GUI) change has drifted from the baseline"* — a correlation the
product had already performed and discarded. The alert that prompted this file
fired at 09:15 UTC for fortiweb08; the cause was an allow-method exception SATOM
itself had inserted at 08:37 UTC (``audit_logs`` 1253-1256, user ``admin`` from
162.23.30.43, via Attack Search). The rows were three feet away and the message
asked the operator to remember.

Nothing raised. Nothing was slow. No test failed — because the code did exactly
what it said, and only the ASSERTION was weaker than the truth. That is the
class this file guards, so almost every test below asserts on the RENDERED
finding rather than on the source: a guard that greps ``alerts.py`` for the old
sentence would match the comment that explains why the sentence is gone.

The two errors are not symmetric, and the tests are weighted accordingly.
Failing to credit a real SATOM write leaves a WARNING that overstates — noisy,
recoverable in two clicks. Crediting a device-side change to SATOM downgrades a
genuine intrusion to an approving nod. Most of what follows pins the second
direction shut: previews, refused writes, GET requests, ``.failed`` twins,
neighbouring appliances and unparseable rows are each proven NOT to count.
"""
from __future__ import annotations

from datetime import datetime, timedelta

from app.models import Appliance, AppSetting, AuditLog, db
from app.models_sot import SotVersion
from app.services import alerts, drift_attribution


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _mk(name="dev1", kind="fortiweb"):
    a = Appliance(name=name, host="192.0.2.99", port=443, kind=kind,
                  username="admin")
    a.password = "pw"
    db.session.add(a)
    db.session.commit()
    return a


def _sot(device, sha, *, taken_min_ago, seen_min_ago=None):
    """A stored version. ``seen_min_ago`` defaults to ``taken`` — the content
    addressed store advances ``last_seen_at`` on every unchanged harvest, so
    the two are independent and the tests need to set them apart."""
    taken = datetime.utcnow() - timedelta(minutes=taken_min_ago)
    seen = (taken if seen_min_ago is None
            else datetime.utcnow() - timedelta(minutes=seen_min_ago))
    row = SotVersion(device=device, sha256=sha, size_raw=10, size_gz=5,
                     total_objects=1, section_count=1, source="harvest",
                     taken_at=taken, last_seen_at=seen)
    db.session.add(row)
    db.session.commit()
    return row


def _audit(action, *, min_ago, extra, target="", user="admin", ip="192.0.2.7"):
    """``extra`` is stored the way ``audit.log_action`` stores it: ``str(dict)``.

    That is a Python repr, not JSON. Building the row any other way would test
    a shape the product never writes.
    """
    db.session.add(AuditLog(
        username=user, action=action, target=target,
        extra=extra if isinstance(extra, str) else str(extra),
        ip_address=ip, timestamp=datetime.utcnow() - timedelta(minutes=min_ago)))
    db.session.commit()


def _fw_detail(*, dry_run=False, error="", mkey="am-exc"):
    """The exact free-text detail ``fortiweb_ops._record`` emits."""
    return f"mkey={mkey} dry_run={dry_run} error={error}"


def _drift_for(slug):
    hits = [f for f in alerts._check_drift() if slug in f["key"]]
    assert len(hits) <= 1, hits
    return hits[0] if hits else None


def _two_versions(slug, *, seen_min_ago=60, new_min_ago=5):
    """Previous version last CONFIRMED unchanged at ``seen_min_ago``, new one
    harvested at ``new_min_ago`` — so the change window is between them."""
    _sot(slug, "a" * 64, taken_min_ago=600, seen_min_ago=seen_min_ago)
    _sot(slug, "b" * 64, taken_min_ago=new_min_ago)


# --------------------------------------------------------------------------
# the positive case
# --------------------------------------------------------------------------

def test_a_recorded_satom_write_is_named_in_the_alert(app):
    with app.app_context():
        a = _mk("dev-att")
        _two_versions("dev-att")
        _audit("config.create", min_ago=30,
               extra={"appliance_id": a.id, "detail": _fw_detail()},
               target="waf/allow-method-exceptions")

        f = _drift_for("dev-att")
        assert f is not None, "an attributed change is still reported"
        assert f["severity"] == alerts.SEV_INFO
        assert "made through SATOM" in f["title"]
        assert "admin" in f["detail"] and "192.0.2.7" in f["detail"]
        assert "config.create" in f["detail"]


def test_the_unattributed_message_states_what_was_searched(app):
    """'No write recorded' is only useful next to the interval searched."""
    with app.app_context():
        _mk("dev-none")
        _two_versions("dev-none")

        f = _drift_for("dev-none")
        assert f["severity"] == alerts.SEV_WARNING
        assert f["title"] == "Config drift on dev-none"
        assert "no write of its own" in f["detail"]
        assert "UTC" in f["detail"] and " to " in f["detail"]
        # The sentence that made the operator do the correlation by hand.
        assert "If nobody edited it via SATOM" not in f["detail"]


def test_the_alert_key_does_not_move_with_attribution(app):
    """The key is the cooldown identity. If it changed when a receipt appeared,
    one config change could notify twice — once as drift, once as credited."""
    with app.app_context():
        a = _mk("dev-key")
        _two_versions("dev-key")
        unattributed = _drift_for("dev-key")["key"]
        _audit("config.update", min_ago=30,
               extra={"appliance_id": a.id, "detail": _fw_detail()})
        assert _drift_for("dev-key")["key"] == unattributed


# --------------------------------------------------------------------------
# the window — the left edge is last_seen_at, not taken_at
# --------------------------------------------------------------------------

def test_the_window_opens_at_last_seen_not_at_taken_at(app):
    """The core of the design, and the reason a naive version misfires.

    An unchanged device mints no row — ``last_seen_at`` advances instead. On
    fortiweb08 the previous version was TAKEN at 00:42 and last CONFIRMED
    unchanged at 08:00, seven hours later. Anchoring on ``taken_at`` opens a
    seven-hour window in which any unrelated morning write can claim the
    evening's drift.
    """
    with app.app_context():
        a = _mk("dev-win")
        # taken 10h ago, but the harvest confirmed it unchanged 1h ago
        _sot("dev-win", "c" * 64, taken_min_ago=600, seen_min_ago=60)
        _sot("dev-win", "d" * 64, taken_min_ago=5)
        # a write 5h ago is AFTER taken_at but BEFORE the config was last
        # confirmed unchanged, so it demonstrably is not the cause
        _audit("config.update", min_ago=300,
               extra={"appliance_id": a.id, "detail": _fw_detail()})

        f = _drift_for("dev-win")
        assert f["severity"] == alerts.SEV_WARNING
        assert "no write of its own" in f["detail"]


def test_a_write_after_the_new_snapshot_is_not_the_cause(app):
    with app.app_context():
        a = _mk("dev-late")
        _sot("dev-late", "e" * 64, taken_min_ago=600, seen_min_ago=60)
        _sot("dev-late", "f" * 64, taken_min_ago=30)
        _audit("config.update", min_ago=2,          # after the snapshot
               extra={"appliance_id": a.id, "detail": _fw_detail()})
        assert _drift_for("dev-late")["severity"] == alerts.SEV_WARNING


def test_window_prefers_the_later_of_taken_and_last_seen(app):
    """A legacy row whose ``last_seen_at`` predates its ``taken_at`` must not
    widen the window leftwards — widening only invents attributions."""
    with app.app_context():
        prev = _sot("dev-legacy", "1" * 64, taken_min_ago=60, seen_min_ago=600)
        new = _sot("dev-legacy", "2" * 64, taken_min_ago=5)
        start, end = drift_attribution.window(prev, new)
        assert start == prev.taken_at
        assert end == new.taken_at


# --------------------------------------------------------------------------
# what must NOT count as a receipt (the dangerous direction)
# --------------------------------------------------------------------------

def test_a_preview_is_not_a_write(app):
    """``fortiweb_ops._record`` logs dry runs with the same action name. A
    preview never touched the device and cannot explain a change on it."""
    with app.app_context():
        a = _mk("dev-dry")
        _two_versions("dev-dry")
        _audit("config.create", min_ago=30,
               extra={"appliance_id": a.id, "detail": _fw_detail(dry_run=True)})
        assert _drift_for("dev-dry")["severity"] == alerts.SEV_WARNING


def test_a_refused_write_is_not_a_write(app):
    """The device said no. Crediting it would retire a real drift alert."""
    with app.app_context():
        a = _mk("dev-err")
        _two_versions("dev-err")
        _audit("config.update", min_ago=30,
               extra={"appliance_id": a.id,
                      "detail": _fw_detail(error="errcode -56 Empty value")})
        assert _drift_for("dev-err")["severity"] == alerts.SEV_WARNING


def test_an_unreadable_detail_is_not_a_write(app):
    """``config.*`` carries its status in free text. If that text cannot be
    read, the honest answer is 'not proven', not 'proven'."""
    with app.app_context():
        a = _mk("dev-mangled")
        _two_versions("dev-mangled")
        _audit("config.update", min_ago=30,
               extra={"appliance_id": a.id, "detail": "who knows"})
        assert _drift_for("dev-mangled")["severity"] == alerts.SEV_WARNING


def test_a_config_row_without_a_detail_is_not_a_write(app):
    """``fortiweb_ops`` always writes the detail string, but nothing in the
    schema enforces it. Absent status is not a proof of success."""
    with app.app_context():
        a = _mk("dev-nodetail")
        _two_versions("dev-nodetail")
        _audit("config.update", min_ago=30, extra={"appliance_id": a.id})
        assert _drift_for("dev-nodetail")["severity"] == alerts.SEV_WARNING


def test_an_errored_api_console_write_is_not_a_write(app):
    """``fac_api.execute`` is logged even when the device refused the call, so
    the row alone proves an ATTEMPT, not a change."""
    with app.app_context():
        _mk("dev-apierr", kind="fortiauthenticator")
        _two_versions("dev-apierr")
        _audit("fac_api.execute", min_ago=30, target="dev-apierr:/api/v1/x",
               extra={"method": "POST", "body": {}, "error": "401 unauthorized"})
        assert _drift_for("dev-apierr")["severity"] == alerts.SEV_WARNING


def test_an_unparseable_extra_is_not_a_write(app):
    with app.app_context():
        _mk("dev-junk")
        _two_versions("dev-junk")
        _audit("config.update", min_ago=30, extra="{not a literal")
        assert _drift_for("dev-junk")["severity"] == alerts.SEV_WARNING


def test_a_failed_faz_device_action_is_not_a_write(app):
    """``faz.device.authorize.failed`` is emitted by the same helper as its
    success twin and sails straight through a ``faz.`` prefix match."""
    with app.app_context():
        a = _mk("dev-faz", kind="fortianalyzer")
        _two_versions("dev-faz")
        _audit("faz.device.authorize.failed", min_ago=30,
               extra={"appliance_id": a.id, "detail": {"error": "boom"}})
        assert _drift_for("dev-faz")["severity"] == alerts.SEV_WARNING


def test_a_read_through_the_api_console_is_not_a_write(app):
    """``faz_api.execute`` / ``adc_api.execute`` are logged for EVERY verb,
    GET included. A read cannot change a config."""
    with app.app_context():
        _mk("dev-get", kind="fortiadc")
        _two_versions("dev-get")
        _audit("adc_api.execute", min_ago=30, target="dev-get",
               extra={"method": "GET", "endpoint": "/api/x"})
        assert _drift_for("dev-get")["severity"] == alerts.SEV_WARNING


def test_a_post_through_the_api_console_is_a_write(app):
    with app.app_context():
        _mk("dev-post", kind="fortiadc")
        _two_versions("dev-post")
        _audit("adc_api.execute", min_ago=30, target="dev-post",
               extra={"method": "POST", "endpoint": "/api/x"})
        f = _drift_for("dev-post")
        assert f["severity"] == alerts.SEV_INFO
        assert "adc_api.execute" in f["detail"]


def test_a_write_to_a_neighbour_never_credits_this_device(app):
    """``appliance_id`` is the only trustworthy link. The FortiAnalyzer's
    ``faz.device.authorize`` names MANAGED devices in its target, so matching
    on the target text would let a FAZ action explain a FortiWeb's drift."""
    with app.app_context():
        _mk("dev-me")
        other = _mk("dev-other", kind="fortianalyzer")
        _two_versions("dev-me")
        _audit("faz.device.authorize", min_ago=30, target="dev-me,dev-x",
               extra={"appliance_id": other.id})
        assert _drift_for("dev-me")["severity"] == alerts.SEV_WARNING


def test_target_matching_uses_the_first_token_only(app):
    """``fac_api.execute`` targets read ``name:/path``. A path segment that
    happens to spell another appliance must not match it."""
    with app.app_context():
        _mk("dev-a", kind="fortiauthenticator")
        _mk("dev-b", kind="fortiauthenticator")
        _two_versions("dev-b")
        _audit("fac_api.execute", min_ago=30,
               target="dev-a:/api/v1/radius/dev-b/",
               extra={"method": "POST", "body": {}})
        assert _drift_for("dev-b")["severity"] == alerts.SEV_WARNING


def test_a_non_write_action_in_the_window_is_ignored(app):
    with app.app_context():
        a = _mk("dev-login")
        _two_versions("dev-login")
        _audit("login", min_ago=30, extra={"appliance_id": a.id})
        _audit("attack_search", min_ago=30, extra={"appliance_id": a.id})
        assert _drift_for("dev-login")["severity"] == alerts.SEV_WARNING


def test_a_dry_run_upgrade_is_not_a_write(app):
    with app.app_context():
        _mk("dev-up")
        _two_versions("dev-up")
        _audit("appliance.upgrade", min_ago=30, target="dev-up",
               extra={"image": "x.out", "dry_run": True, "error": ""})
        assert _drift_for("dev-up")["severity"] == alerts.SEV_WARNING


def test_a_real_upgrade_is_a_write(app):
    with app.app_context():
        _mk("dev-up2")
        _two_versions("dev-up2")
        _audit("appliance.upgrade", min_ago=30, target="dev-up2",
               extra={"image": "x.out", "dry_run": False, "error": ""})
        assert _drift_for("dev-up2")["severity"] == alerts.SEV_INFO


# --------------------------------------------------------------------------
# the repr trap
# --------------------------------------------------------------------------

def test_extra_is_read_as_a_python_repr_not_as_json(app):
    """``audit.log_action`` stores ``str(extra)``. ``json.loads`` fails on every
    row ever written (single quotes, ``True``) — and a reader that silently
    returned ``{}`` would make EVERY device look unattributed, which is exactly
    the bug this module exists to remove, reintroduced one layer down."""
    with app.app_context():
        raw = str({"appliance_id": 7, "detail": "mkey=x dry_run=False error="})
        assert "'" in raw and '"' not in raw
        assert drift_attribution._extra(raw)["appliance_id"] == 7


# --------------------------------------------------------------------------
# the operator lever
# --------------------------------------------------------------------------

def test_attributed_changes_can_be_silenced(app):
    with app.app_context():
        a = _mk("dev-off")
        _two_versions("dev-off")
        _audit("config.create", min_ago=30,
               extra={"appliance_id": a.id, "detail": _fw_detail()})
        AppSetting.set(alerts.K_DRIFT_ATTRIBUTED, "off")
        assert _drift_for("dev-off") is None


def test_attributed_changes_can_be_kept_at_warning(app):
    """An install that wants every config change to shout keeps the severity
    and gains the authorship."""
    with app.app_context():
        a = _mk("dev-warn")
        _two_versions("dev-warn")
        _audit("config.create", min_ago=30,
               extra={"appliance_id": a.id, "detail": _fw_detail()})
        AppSetting.set(alerts.K_DRIFT_ATTRIBUTED, "warn")
        f = _drift_for("dev-warn")
        assert f["severity"] == alerts.SEV_WARNING
        assert "made through SATOM" in f["title"]


def test_an_unknown_setting_value_falls_back_to_reporting(app):
    """A typo in a setting must not silence an alert."""
    with app.app_context():
        a = _mk("dev-typo")
        _two_versions("dev-typo")
        _audit("config.create", min_ago=30,
               extra={"appliance_id": a.id, "detail": _fw_detail()})
        AppSetting.set(alerts.K_DRIFT_ATTRIBUTED, "banana")
        assert _drift_for("dev-typo")["severity"] == alerts.SEV_INFO


# --------------------------------------------------------------------------
# failure modes
# --------------------------------------------------------------------------

def test_a_broken_audit_read_degrades_to_unattributed(app, monkeypatch):
    """Attribution is an enrichment. If it breaks, the drift alert must still
    fire — and must fire as the LOUDER of the two shapes."""
    with app.app_context():
        _mk("dev-boom")
        _two_versions("dev-boom")

        def _boom(*_a, **_k):
            raise RuntimeError("audit table gone")

        monkeypatch.setattr(drift_attribution, "receipts", _boom)
        f = _drift_for("dev-boom")
        assert f is not None and f["severity"] == alerts.SEV_WARNING


def test_a_nonsense_window_never_reaches_the_audit_table(app, monkeypatch):
    """Asserting only that the result is empty proves nothing here: a query
    with ``timestamp >= NULL`` or a backwards range returns no rows anyway, so
    that assertion holds with the guard deleted. What the guard is FOR is not
    issuing the query, so that is what is asserted."""
    class _Boom:
        def __getattr__(self, name):
            raise AssertionError("queried the audit table on a nonsense window")

    with app.app_context():
        a = _mk("dev-rev")
        now = datetime.utcnow()
        monkeypatch.setattr(AuditLog, "query", _Boom())
        assert drift_attribution.receipts(a, now, now - timedelta(hours=1)) == []
        assert drift_attribution.receipts(a, None, now) == []
        assert drift_attribution.receipts(a, now, None) == []
        assert drift_attribution.receipts(None, now, now) == []


def test_the_span_phrase_survives_a_missing_edge(app):
    with app.app_context():
        assert "previous snapshot" in alerts._span({"start": None, "end": None})


# --------------------------------------------------------------------------
# the console surface
# --------------------------------------------------------------------------

def test_the_console_round_trips_the_lever(app):
    with app.app_context():
        alerts.save_config({"drift_attributed": "off"})
        assert alerts.config()["drift_attributed"] == "off"
        alerts.save_config({"drift_attributed": "warn"})
        assert alerts.config()["drift_attributed"] == "warn"


def test_a_bogus_lever_value_falls_back_to_reporting_not_to_silence(app):
    """The two invalid-value outcomes are not equally harmless: falling back to
    "off" would let a typo in a settings field mute a whole check."""
    with app.app_context():
        alerts.save_config({"drift_attributed": ""})
        assert alerts.config()["drift_attributed"] == "info"
        alerts.save_config({"drift_attributed": "quiet"})
        assert alerts.config()["drift_attributed"] == "info"


def test_the_lever_is_reachable_from_the_settings_form(app):
    """Anchored on the FIELD NAME, which is the contract between template and
    save_config — not on the rendered label, which i18n owns and which is
    how the Administrator nav guard quietly stopped guarding (safeguards 68)."""
    import re
    from pathlib import Path
    html = Path(app.root_path, "templates/settings/index.html").read_text()
    assert 'name="drift_attributed"' in html
    block = html.split('name="drift_attributed"', 1)[1].split("</select>", 1)[0]
    assert set(re.findall(r'<option value="([a-z]+)"', block)) == {"info", "warn", "off"}
