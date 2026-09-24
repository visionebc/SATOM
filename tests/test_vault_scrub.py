"""Guards for scrubbing the local copies (the step that closes the exposure).

The claim they defend, in one line: **the mode moves nothing**. Switching to
"vault only" only decides where the NEXT write goes; as long as the Fernet
column still holds the password, the key that decrypts it sits on the same
disk and the hole stays open. These guards pin down both halves:

1. that the scrub really happens (an attacker with .env gets nothing out), and
2. that it NEVER deletes a local copy without having read an identical copy
   back from the vault — destroying the last copy of a credential is the only
   failure here that no later step can undo.
"""
import pytest

from app.models import Appliance, AppSetting, db
from app.services import encryption, secret_backend as sb

from conftest import admin_user_id, login, make_user
from test_secret_backend import configure, make_appliance, vault  # noqa: F401


def _local(name):
    row = Appliance.query.filter_by(name=name).first()
    return encryption.decrypt(row.password_enc)


def _status(res, name):
    for item in res["items"]:
        if item["name"] == name:
            return item["status"]
    return None


def _detail(res, name):
    for item in res["items"]:
        if item["name"] == name:
            return item["detail"]
    return None


# ---------------------------------------------------------------------------
# 1. the mode rules: without "vault only" nothing is deleted
# ---------------------------------------------------------------------------
def test_scrub_is_refused_in_mirror_mode_and_the_local_copy_survives(app, vault):
    """mirror exists BECAUSE of the local copy: removing it turns it into vault-only."""
    with app.app_context():
        configure(sb.MODE_MIRROR)
        make_appliance("fw1", "s3cr3t")
        res = sb.scrub_local_copies(dry_run=False)
        assert res["ok"] is False
        assert "error" in res
        assert res["scrubbed"] == 0
        assert _local("fw1") == "s3cr3t"


def test_scrub_is_refused_in_local_mode(app):
    with app.app_context():
        make_appliance("fw1", "s3cr3t")
        res = sb.scrub_local_copies(dry_run=False)
        assert res["ok"] is False
        assert res["scrubbed"] == 0
        assert _local("fw1") == "s3cr3t"


def test_scrub_is_refused_while_the_switch_is_off(app, vault):
    """Vault mode but the switch off = the vault is not in the path."""
    with app.app_context():
        configure(sb.MODE_MIRROR)
        make_appliance("fw1", "s3cr3t")
        sb.save({"enabled": False, "mode": sb.MODE_VAULT,
                 "addr": "https://vault.test:8200", "role_id": "rid"})
        res = sb.scrub_local_copies(dry_run=False)
        assert res["ok"] is False
        assert _local("fw1") == "s3cr3t"


# ---------------------------------------------------------------------------
# 2. dry run
# ---------------------------------------------------------------------------
def test_dry_run_reports_the_work_without_doing_it(app, vault):
    with app.app_context():
        configure(sb.MODE_MIRROR)
        make_appliance("fw1", "s3cr3t")        # ends up in both copies
        configure(sb.MODE_VAULT)
        res = sb.scrub_local_copies(dry_run=True)
        assert res["dry_run"] is True
        assert res["ok"] is True
        assert _status(res, "fw1") == "scrubbed"
        assert res["scrubbed"] == 1
        assert _local("fw1") == "s3cr3t"       # untouched


# ---------------------------------------------------------------------------
# 3. the real scrub
# ---------------------------------------------------------------------------
def test_apply_replaces_the_local_copy_with_the_sentinel(app, vault):
    with app.app_context():
        configure(sb.MODE_MIRROR)
        make_appliance("fw1", "s3cr3t")
        configure(sb.MODE_VAULT)
        res = sb.scrub_local_copies(dry_run=False)
        assert res["ok"] is True and res["scrubbed"] == 1
        assert _local("fw1") == sb.VAULT_SENTINEL


def test_the_password_still_reads_after_the_scrub(app, vault):
    """Deleting the local copy cannot break normal use."""
    with app.app_context():
        configure(sb.MODE_MIRROR)
        row = make_appliance("fw1", "s3cr3t")
        configure(sb.MODE_VAULT)
        sb.scrub_local_copies(dry_run=False)
        assert row.password == "s3cr3t"


def test_after_the_scrub_the_fernet_key_alone_recovers_nothing(app, vault):
    """The feature's whole claim, written as an assertion.

    Whoever steals the disk and .env decrypts the column: what comes out has to
    be the sentinel, not the password.
    """
    with app.app_context():
        configure(sb.MODE_MIRROR)
        make_appliance("fw1", "s3cr3t")
        configure(sb.MODE_VAULT)
        sb.scrub_local_copies(dry_run=False)
        stolen = encryption.decrypt(
            Appliance.query.filter_by(name="fw1").first().password_enc)
        assert stolen != "s3cr3t"
        assert stolen == sb.VAULT_SENTINEL


# ---------------------------------------------------------------------------
# 4. what is NEVER deleted
# ---------------------------------------------------------------------------
def test_a_row_the_vault_does_not_hold_keeps_its_local_copy(app, vault):
    """The case that justifies the read-back: with no remote copy, the local one is the last."""
    with app.app_context():
        configure(sb.MODE_MIRROR)
        make_appliance("fw1", "s3cr3t")
        vault.store.pop("appliances/fw1", None)      # the vault does not have it
        configure(sb.MODE_VAULT)
        res = sb.scrub_local_copies(dry_run=False)
        assert res["ok"] is False
        assert _status(res, "fw1") == "failed"
        assert res["scrubbed"] == 0
        assert _local("fw1") == "s3cr3t"
        # "does not have it" and "has a different one" are fixed differently:
        # a message that confuses them sends the operator to the wrong place.
        assert "no copy in the vault" in _detail(res, "fw1")


def test_a_vault_copy_that_differs_is_never_treated_as_a_backup(app, vault):
    with app.app_context():
        configure(sb.MODE_MIRROR)
        make_appliance("fw1", "s3cr3t")
        vault.store["appliances/fw1"]["password"] = "something-else"
        configure(sb.MODE_VAULT)
        res = sb.scrub_local_copies(dry_run=False)
        assert res["ok"] is False
        assert _status(res, "fw1") == "failed"
        assert "differs" in _detail(res, "fw1")
        assert _local("fw1") == "s3cr3t"


def test_a_vault_that_is_down_scrubs_nothing(app, vault):
    with app.app_context():
        configure(sb.MODE_MIRROR)
        make_appliance("fw1", "s3cr3t")
        configure(sb.MODE_VAULT)
        vault.fail_reads = True
        res = sb.scrub_local_copies(dry_run=False)
        assert res["ok"] is False
        assert res["scrubbed"] == 0
        assert _local("fw1") == "s3cr3t"


def test_one_bad_row_does_not_stop_the_good_ones(app, vault):
    with app.app_context():
        configure(sb.MODE_MIRROR)
        make_appliance("fw1", "s3cr3t")
        make_appliance("fw2", "another")
        vault.store.pop("appliances/fw2", None)
        configure(sb.MODE_VAULT)
        res = sb.scrub_local_copies(dry_run=False)
        assert _status(res, "fw1") == "scrubbed"
        assert _status(res, "fw2") == "failed"
        assert _local("fw1") == sb.VAULT_SENTINEL
        assert _local("fw2") == "another"
        assert res["ok"] is False


# ---------------------------------------------------------------------------
# 5. idempotency
# ---------------------------------------------------------------------------
def test_running_it_twice_is_a_no_op_the_second_time(app, vault):
    with app.app_context():
        configure(sb.MODE_MIRROR)
        make_appliance("fw1", "s3cr3t")
        configure(sb.MODE_VAULT)
        sb.scrub_local_copies(dry_run=False)
        again = sb.scrub_local_copies(dry_run=False)
        assert again["ok"] is True
        assert again["scrubbed"] == 0
        assert _status(again, "fw1") == "skipped"


def test_a_row_without_a_password_is_skipped_not_failed(app, vault):
    with app.app_context():
        configure(sb.MODE_VAULT)
        row = Appliance(name="fw9", kind="fortiweb", host="192.0.2.9",
                        port=443, username="admin", password_enc="")
        db.session.add(row)
        db.session.commit()
        res = sb.scrub_local_copies(dry_run=False)
        assert _status(res, "fw9") == "skipped"
        assert res["ok"] is True


# ---------------------------------------------------------------------------
# 6. the directory secrets
# ---------------------------------------------------------------------------
def test_the_radius_shared_secret_is_scrubbed_and_still_reads(app, vault):
    with app.app_context():
        configure(sb.MODE_MIRROR)
        AppSetting.set("auth.radius.secret_enc", encryption.encrypt("radius-pw"))
        sb.put_field("auth/fortiauthenticator", "shared_secret", "radius-pw")
        configure(sb.MODE_VAULT)
        res = sb.scrub_local_copies(dry_run=False)
        assert _status(res, "FortiAuthenticator shared secret") == "scrubbed"
        assert encryption.decrypt(
            AppSetting.get("auth.radius.secret_enc")) == sb.VAULT_SENTINEL
        assert sb.get_field("auth/fortiauthenticator", "shared_secret") == "radius-pw"


def test_a_directory_secret_missing_from_the_vault_is_not_destroyed(app, vault):
    with app.app_context():
        configure(sb.MODE_VAULT)
        AppSetting.set("auth.ldap.bind_password_enc", encryption.encrypt("bind-pw"))
        res = sb.scrub_local_copies(dry_run=False)
        assert _status(res, "LDAP/AD bind password") == "failed"
        assert "no copy in the vault" in _detail(res, "LDAP/AD bind password")
        assert encryption.decrypt(
            AppSetting.get("auth.ldap.bind_password_enc")) == "bind-pw"
        assert res["ok"] is False


def test_a_directory_secret_that_is_not_configured_is_skipped(app, vault):
    with app.app_context():
        configure(sb.MODE_VAULT)
        res = sb.scrub_local_copies(dry_run=False)
        assert _status(res, "LDAP/AD bind password") == "skipped"
        assert res["ok"] is True


# ---------------------------------------------------------------------------
# 7. the route
# ---------------------------------------------------------------------------
def _ready(app):
    with app.app_context():
        configure(sb.MODE_MIRROR)
        make_appliance("fw1", "s3cr3t")
        configure(sb.MODE_VAULT)


def test_the_route_without_apply_destroys_nothing(app, client, vault):
    """A POST that forgets ``apply`` cannot delete credentials."""
    _ready(app)
    login(client, admin_user_id(app))
    body = client.post("/settings/vault/scrub").get_json()
    assert body["dry_run"] is True
    assert body["scrubbed"] == 1
    with app.app_context():
        assert _local("fw1") == "s3cr3t"


def test_the_route_applies_only_with_apply_1(app, client, vault):
    _ready(app)
    login(client, admin_user_id(app))
    body = client.post("/settings/vault/scrub", data={"apply": "1"}).get_json()
    assert body["dry_run"] is False
    assert body["scrubbed"] == 1
    with app.app_context():
        assert _local("fw1") == sb.VAULT_SENTINEL


def test_a_read_only_user_cannot_scrub(app, client, vault):
    _ready(app)
    uid = make_user(app, username="reader", role="readonly")
    login(client, uid)
    resp = client.post("/settings/vault/scrub", data={"apply": "1"})
    assert resp.status_code != 200
    with app.app_context():
        assert _local("fw1") == "s3cr3t"


def test_the_service_default_is_the_dry_run(app):
    import inspect
    assert inspect.signature(
        sb.scrub_local_copies).parameters["dry_run"].default is True
