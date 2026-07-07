# tests/test_cert_lifecycle.py — lifecycle policy (revoke/delete windows),
# protocol selection (ADCS/ACME) and the hardened command-template argv builder.
from datetime import datetime, timedelta

import pytest

from app.services import cert_manager as cm
from app.services import settings_store as store


# --------------------------------------------------------------------------- #
#  Command construction — parse-then-substitute (no argv injection)             #
# --------------------------------------------------------------------------- #
def test_argv_from_template_keeps_secret_as_one_argument():
    argv = cm._argv_from_template(
        "certipy req -u {user}@{domain} -p {password} -ca {ca_name}",
        {"user": "svc", "domain": "corp.local",
         "password": "p4ss word' -evil --flag", "ca_name": "CORP CA"})
    # argv: [certipy, req, -u, svc@corp.local, -p, <password>, -ca, CORP CA]
    # The password stays ONE argv element — spaces/quotes cannot inject args.
    assert argv[5] == "p4ss word' -evil --flag"
    assert argv[7] == "CORP CA"
    assert "--flag" not in argv  # never a standalone injected argument


def test_argv_from_template_rejects_broken_template():
    with pytest.raises(cm.CertManagerError):
        cm._argv_from_template("certipy 'unclosed", {})
    with pytest.raises(cm.CertManagerError):
        cm._argv_from_template("", {})


# --------------------------------------------------------------------------- #
#  Protocol selection + settings round-trip                                     #
# --------------------------------------------------------------------------- #
def test_protocol_roundtrip_and_default(app):
    with app.app_context():
        assert store.cert_manager_protocol() == "adcs"
        store.save_cert_manager_protocol("acme")
        assert store.cert_manager_protocol() == "acme"
        store.save_cert_manager_protocol("bogus")  # ignored
        assert store.cert_manager_protocol() == "acme"
        store.save_cert_manager_protocol("adcs")


def test_acme_config_roundtrip_encrypts_hmac(app):
    with app.app_context():
        store.save_cert_manager_acme({
            "directory_url": "https://acme.corp.local/dir",
            "account_email": "pki@corp.local",
            "eab_kid": "kid-1", "eab_hmac": "topsecret",
            "challenge": "dns-01",
        })
        cfg = store.cert_manager_acme()
        assert cfg["directory_url"] == "https://acme.corp.local/dir"
        assert cfg["challenge"] == "dns-01"
        assert cfg["has_secret"] is True
        assert cfg["eab_hmac"] == ""  # hidden unless revealed
        assert store.cert_manager_acme(reveal_secret=True)["eab_hmac"] == "topsecret"
        # raw storage is encrypted, never plaintext
        raw = store.get_json(store.K_CERTMGR_ACME, {})
        assert "topsecret" not in (raw.get("eab_hmac_enc") or "")


def test_signing_context_follows_protocol(app):
    with app.app_context():
        store.save_cert_manager_protocol("acme")
        store.save_cert_manager_acme({"directory_url": "https://acme/dir",
                                      "account_email": "a@b"})
        proto, tmpl, mapping, _ = cm._signing_context("server")
        assert proto == "acme"
        assert "{csr}" in tmpl and "certonly" in tmpl
        assert mapping["directory"] == "https://acme/dir"
        store.save_cert_manager_protocol("adcs")
        proto, tmpl, mapping, _ = cm._signing_context("server")
        assert proto == "adcs"
        assert "certipy req" in tmpl
        assert "template" in mapping


def test_cert_manager_configured_is_protocol_aware(app):
    with app.app_context():
        store.save_cert_manager_protocol("acme")
        store.save_cert_manager_acme({"directory_url": "https://acme/dir"})
        assert store.cert_manager_configured() is True
        store.save_cert_manager_protocol("adcs")
        assert store.cert_manager_configured() is False  # no ADCS CA configured


# --------------------------------------------------------------------------- #
#  Lifecycle policy — candidates                                                #
# --------------------------------------------------------------------------- #
def _mk_cert(app, name, status, *, appliance_id=1, superseded_days=None,
             expired_days=None, bound=()):
    from app.models import ManagedCertificate, db
    c = ManagedCertificate(name=name, appliance_id=appliance_id,
                           cert_class="server", status=status)
    if superseded_days is not None:
        c.superseded_at = datetime.utcnow() - timedelta(days=superseded_days)
    if expired_days is not None:
        c.expires_at = datetime.utcnow() - timedelta(days=expired_days)
    c.bound_policies = list(bound)
    db.session.add(c)
    db.session.commit()
    return c


def test_lifecycle_policy_roundtrip(app):
    with app.app_context():
        pol = store.cert_lifecycle_policy()
        assert pol["revoke_on_supersede"] is True
        assert pol["auto_apply"] is False
        store.save_cert_lifecycle_policy({
            "revoke_on_supersede": False, "revoke_grace_days": "3",
            "delete_superseded_after_days": 5, "delete_expired_after_days": "x",
            "delete_revoked_from_device": False, "auto_apply": True})
        pol = store.cert_lifecycle_policy()
        assert pol["revoke_on_supersede"] is False
        assert pol["revoke_grace_days"] == 3
        assert pol["delete_superseded_after_days"] == 5
        assert pol["delete_expired_after_days"] == 30  # bad value -> default kept
        assert pol["auto_apply"] is True


def test_candidates_revoke_after_grace_and_blocked_when_bound(app):
    with app.app_context():
        store.save_cert_lifecycle_policy({"revoke_on_supersede": True,
                                          "revoke_grace_days": 7,
                                          "delete_superseded_after_days": 14,
                                          "delete_expired_after_days": 30,
                                          "delete_revoked_from_device": True,
                                          "auto_apply": False})
        _mk_cert(app, "old-due", "superseded", superseded_days=10)
        _mk_cert(app, "old-fresh", "superseded", superseded_days=2)
        _mk_cert(app, "old-bound", "superseded", superseded_days=10,
                 bound=("pol-a",))
        cand = cm.lifecycle_candidates()
        revoke_names = [i["cert"].name for i in cand["revoke_due"]]
        blocked = [i["cert"].name for i in cand["blocked"]]
        assert revoke_names == ["old-due"]
        assert "old-fresh" not in revoke_names
        assert "old-bound" in blocked


def test_candidates_delete_rules(app):
    with app.app_context():
        store.save_cert_lifecycle_policy({"revoke_on_supersede": False,
                                          "revoke_grace_days": 7,
                                          "delete_superseded_after_days": 14,
                                          "delete_expired_after_days": 30,
                                          "delete_revoked_from_device": True,
                                          "auto_apply": False})
        _mk_cert(app, "rev", "revoked")                        # due (revoked)
        _mk_cert(app, "sup-old", "superseded", superseded_days=20)   # due (retention)
        _mk_cert(app, "sup-new", "superseded", superseded_days=5)    # not yet
        _mk_cert(app, "exp-old", "active", expired_days=40)          # due (expired)
        _mk_cert(app, "exp-new", "active", expired_days=5)           # not yet
        cand = cm.lifecycle_candidates()
        names = [i["cert"].name for i in cand["delete_due"]]
        assert set(names) == {"rev", "sup-old", "exp-old"}


def test_sweep_dry_run_reports_without_touching(app, monkeypatch):
    with app.app_context():
        store.save_cert_lifecycle_policy({"revoke_on_supersede": True,
                                          "revoke_grace_days": 7,
                                          "delete_superseded_after_days": 14,
                                          "delete_expired_after_days": 30,
                                          "delete_revoked_from_device": True,
                                          "auto_apply": False})
        c = _mk_cert(app, "old-due", "superseded", superseded_days=10)
        monkeypatch.setattr(cm, "read_bindings_for", lambda cert: [])
        res = cm.run_lifecycle_sweep(dry_run=True)
        assert res["dry_run"] is True
        assert any("old-due" in line for line in res["revoked"])
        assert c.status == "superseded"  # untouched


def test_sweep_fail_closed_on_unreadable_bindings(app, monkeypatch):
    with app.app_context():
        store.save_cert_lifecycle_policy({"revoke_on_supersede": True,
                                          "revoke_grace_days": 7,
                                          "delete_superseded_after_days": 14,
                                          "delete_expired_after_days": 30,
                                          "delete_revoked_from_device": False,
                                          "auto_apply": False})
        c = _mk_cert(app, "old-due", "superseded", superseded_days=10)

        def _boom(cert):
            raise RuntimeError("box unreachable")
        monkeypatch.setattr(cm, "read_bindings_for", _boom)
        res = cm.run_lifecycle_sweep(dry_run=False)
        assert not res["revoked"]
        assert any("fail-closed" in line for line in res["skipped"])
        assert c.status == "superseded"  # never revoked blind
