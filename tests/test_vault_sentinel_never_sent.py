"""The sentinel is not a credential and cannot go out the door as if it were one.

What this pins down: when the local column says `__stored-in-vault__` and the
vault is NOT in THIS process's path, there is nothing to send. Returning the
marker puts the literal string into a login form: the appliance answers 401 and
the operator reads "wrong password" instead of "this process cannot reach the
vault".

This is not hypothetical. On 2026-08-19, the same day the local copies were
scrubbed, `satom-scheduler` was still running pre-vault code (process started
on 17 August). Its getter only read the local column, sent the sentinel to
every appliance, and the entire fleet sweep went to 401 —
`satom_scrape_up` dropped from 1 to 0 without a single line in the vault's
audit log, which was precisely the clue that nobody was asking the vault.
"""
import pytest

from app.models import Appliance, AppSetting, db
from app.services import auth_store, encryption, secret_backend as sb

from test_secret_backend import configure, make_appliance, vault  # noqa: F401


def _sentinel_row(name="fw1"):
    row = Appliance(name=name, kind="fortiweb", host="192.0.2.1", port=443,
                    username="admin",
                    password_enc=encryption.encrypt(sb.VAULT_SENTINEL))
    db.session.add(row)
    db.session.commit()
    return row


def test_the_sentinel_is_never_returned_as_a_password(app):
    """Local mode (or a process without the vault in its path) + sentinel column."""
    with app.app_context():
        row = _sentinel_row()
        with pytest.raises(RuntimeError) as exc:
            row.password
        assert "vault" in str(exc.value).lower()
        assert sb.VAULT_SENTINEL not in str(exc.value) or "owns" in str(exc.value)


def test_the_error_names_the_appliance(app):
    """A failure that does not say WHICH one sends you to check all nine."""
    with app.app_context():
        row = _sentinel_row("fortiweb12")
        with pytest.raises(RuntimeError) as exc:
            row.password
        assert "fortiweb12" in str(exc.value)


def test_a_normal_password_still_reads(app):
    with app.app_context():
        row = make_appliance("fw2", "s3cr3t")
        assert row.password == "s3cr3t"


def test_the_vault_copy_wins_over_the_sentinel(app, vault):
    """With the vault in the path the column is not even looked at."""
    with app.app_context():
        configure(sb.MODE_VAULT)
        row = _sentinel_row("fw3")
        sb.write(sb.appliance_path("fw3"), {"password": "from-the-vault"})
        assert row.password == "from-the-vault"


def test_the_directory_secret_sentinel_is_never_returned(app):
    with app.app_context():
        AppSetting.set("auth.radius.secret_enc",
                       encryption.encrypt(sb.VAULT_SENTINEL))
        with pytest.raises(RuntimeError) as exc:
            auth_store._vault_first("auth/fortiauthenticator", "shared_secret",
                                    "auth.radius.secret_enc")
        assert "vault" in str(exc.value).lower()


def test_a_normal_directory_secret_still_reads(app):
    with app.app_context():
        AppSetting.set("auth.radius.secret_enc", encryption.encrypt("radius-pw"))
        assert auth_store._vault_first(
            "auth/fortiauthenticator", "shared_secret",
            "auth.radius.secret_enc") == "radius-pw"


def test_an_unset_directory_secret_is_still_empty_not_an_error(app):
    """Unconfigured is still "" — the guard only looks at the sentinel."""
    with app.app_context():
        assert auth_store._vault_first(
            "auth/fortiauthenticator", "shared_secret",
            "auth.radius.secret_enc") == ""
