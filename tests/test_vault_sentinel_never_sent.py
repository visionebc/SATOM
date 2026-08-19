"""El centinela no es una credencial y no puede salir por la puerta como si lo fuera.

Lo que fija: cuando la columna local dice `__stored-in-vault__` y el vault NO
esta en el camino de ESTE proceso, no hay nada que enviar. Devolver el marcador
mete la cadena literal en un formulario de login: el aparato contesta 401 y el
operador lee "contrasena incorrecta" en vez de "este proceso no llega al vault".

No es hipotetico. El 2026-08-19, el mismo dia que se borraron las copias
locales, `satom-scheduler` seguia corriendo codigo anterior al vault (proceso
arrancado el 17 de agosto). Su getter solo leia la columna local, mando el
centinela a cada aparato y el barrido de flota entero paso a 401 —
`satom_scrape_up` cayo de 1 a 0 sin una sola linea en el audit log del vault,
que era justamente la pista de que nadie estaba preguntandole al vault.
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
    """Modo local (o proceso sin el vault en el camino) + columna centinela."""
    with app.app_context():
        row = _sentinel_row()
        with pytest.raises(RuntimeError) as exc:
            row.password
        assert "vault" in str(exc.value).lower()
        assert sb.VAULT_SENTINEL not in str(exc.value) or "owns" in str(exc.value)


def test_the_error_names_the_appliance(app):
    """Un fallo que no dice CUAL manda a revisar los nueve."""
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
    """Con el vault en el camino la columna no se mira siquiera."""
    with app.app_context():
        configure(sb.MODE_VAULT)
        row = _sentinel_row("fw3")
        sb.write(sb.appliance_path("fw3"), {"password": "desde-el-vault"})
        assert row.password == "desde-el-vault"


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
    """Sin configurar sigue siendo "" — el guardia solo mira el centinela."""
    with app.app_context():
        assert auth_store._vault_first(
            "auth/fortiauthenticator", "shared_secret",
            "auth.radius.secret_enc") == ""
