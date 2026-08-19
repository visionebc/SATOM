"""Guardias del borrado de las copias locales (paso que cierra la exposicion).

La afirmacion que defienden, en una linea: **el modo no mueve nada**. Cambiar a
"vault only" solo decide donde va la SIGUIENTE escritura; mientras la columna
Fernet siga teniendo la contrasena, la clave que la descifra sigue en el mismo
disco y el agujero sigue abierto. Estos guardias fijan las dos mitades:

1. que el borrado ocurra de verdad (el atacante con .env ya no saca nada), y
2. que NUNCA borre una copia local sin haber leido del vault una copia
   identica — destruir la ultima copia de una credencial es el unico fallo
   aqui que ningun paso posterior puede deshacer.
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
# 1. el modo manda: sin "vault only" no se borra nada
# ---------------------------------------------------------------------------
def test_scrub_is_refused_in_mirror_mode_and_the_local_copy_survives(app, vault):
    """mirror existe POR la copia local: quitarla lo convierte en vault-only."""
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
    """Modo vault pero interruptor apagado = el vault no esta en el camino."""
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
        make_appliance("fw1", "s3cr3t")        # queda en las dos copias
        configure(sb.MODE_VAULT)
        res = sb.scrub_local_copies(dry_run=True)
        assert res["dry_run"] is True
        assert res["ok"] is True
        assert _status(res, "fw1") == "scrubbed"
        assert res["scrubbed"] == 1
        assert _local("fw1") == "s3cr3t"       # intacta


# ---------------------------------------------------------------------------
# 3. el borrado real
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
    """Borrar la copia local no puede romper el uso normal."""
    with app.app_context():
        configure(sb.MODE_MIRROR)
        row = make_appliance("fw1", "s3cr3t")
        configure(sb.MODE_VAULT)
        sb.scrub_local_copies(dry_run=False)
        assert row.password == "s3cr3t"


def test_after_the_scrub_the_fernet_key_alone_recovers_nothing(app, vault):
    """La afirmacion entera del feature, escrita como aserto.

    Quien roba disco y .env descifra la columna: tiene que salir el centinela,
    no la contrasena.
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
# 4. lo que NUNCA se borra
# ---------------------------------------------------------------------------
def test_a_row_the_vault_does_not_hold_keeps_its_local_copy(app, vault):
    """El caso que justifica el read-back: sin copia remota, la local es la ultima."""
    with app.app_context():
        configure(sb.MODE_MIRROR)
        make_appliance("fw1", "s3cr3t")
        vault.store.pop("appliances/fw1", None)      # el vault no la tiene
        configure(sb.MODE_VAULT)
        res = sb.scrub_local_copies(dry_run=False)
        assert res["ok"] is False
        assert _status(res, "fw1") == "failed"
        assert res["scrubbed"] == 0
        assert _local("fw1") == "s3cr3t"
        # "no la tiene" y "la tiene distinta" se arreglan de forma distinta:
        # un mensaje que los confunde manda al operador al sitio equivocado.
        assert "no copy in the vault" in _detail(res, "fw1")


def test_a_vault_copy_that_differs_is_never_treated_as_a_backup(app, vault):
    with app.app_context():
        configure(sb.MODE_MIRROR)
        make_appliance("fw1", "s3cr3t")
        vault.store["appliances/fw1"]["password"] = "otra-cosa"
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
        make_appliance("fw2", "otra")
        vault.store.pop("appliances/fw2", None)
        configure(sb.MODE_VAULT)
        res = sb.scrub_local_copies(dry_run=False)
        assert _status(res, "fw1") == "scrubbed"
        assert _status(res, "fw2") == "failed"
        assert _local("fw1") == sb.VAULT_SENTINEL
        assert _local("fw2") == "otra"
        assert res["ok"] is False


# ---------------------------------------------------------------------------
# 5. idempotencia
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
# 6. los secretos de directorio
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
# 7. la ruta
# ---------------------------------------------------------------------------
def _ready(app):
    with app.app_context():
        configure(sb.MODE_MIRROR)
        make_appliance("fw1", "s3cr3t")
        configure(sb.MODE_VAULT)


def test_the_route_without_apply_destroys_nothing(app, client, vault):
    """Un POST que olvida ``apply`` no puede borrar credenciales."""
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
    uid = make_user(app, username="lector", role="readonly")
    login(client, uid)
    resp = client.post("/settings/vault/scrub", data={"apply": "1"})
    assert resp.status_code != 200
    with app.app_context():
        assert _local("fw1") == "s3cr3t"


def test_the_service_default_is_the_dry_run(app):
    import inspect
    assert inspect.signature(
        sb.scrub_local_copies).parameters["dry_run"].default is True
