"""Guardias del backend de secretos (local Fernet <-> vault externo).

Lo que estos guardias defienden, en una linea: **anadir el vault no puede
cambiar el comportamiento de una instalacion que no lo configura**, y cuando el
vault SI es la unica copia, un fallo tiene que ROMPER en vez de degradar a una
contrasena vacia o a un centinela.

No hablan con ningun vault real: la capa de transporte (``_request``) se
sustituye por un doble que ademas CUENTA las llamadas, porque media docena de
estos defectos solo se ven en el numero de peticiones, no en el resultado.
"""
import json

import pytest

from app.models import Appliance, AppSetting, db
from app.services import encryption, secret_backend as sb


# ---------------------------------------------------------------------------
# dobles
# ---------------------------------------------------------------------------
class FakeVault:
    """Un KV v2 en memoria con contador de llamadas."""

    def __init__(self, fail_reads=False, fail_login=False):
        self.store = {}
        self.calls = []
        self.logins = 0
        self.fail_reads = fail_reads
        self.fail_login = fail_login

    def __call__(self, cfg, method, path, token="", body=None):
        self.calls.append((method, path))
        if path == "auth/approle/login":
            if self.fail_login:
                raise sb.VaultError("login rechazado")
            self.logins += 1
            return {"auth": {"client_token": "tok-%d" % self.logins,
                             "lease_duration": 3600,
                             "token_policies": ["satom-app"]}}
        if path == "sys/health":
            return {"sealed": False, "version": "2.6.2"}
        if path == "auth/token/lookup-self":
            return {"data": {"policies": ["satom-app"]}}
        if path.endswith("/metadata?list=true"):
            return {"data": {"keys": []}}
        # KV v2: "<mount>/data/<ruta>"
        mount, _, rest = path.partition("/data/")
        if method == "GET":
            if self.fail_reads:
                raise sb.VaultError("GET %s -> vault caido" % path)
            if rest not in self.store:
                raise sb.VaultError("GET %s -> HTTP 404" % path)
            return {"data": {"data": dict(self.store[rest])}}
        if method == "POST":
            self.store[rest] = dict((body or {}).get("data") or {})
            return {"data": {"version": 1}}
        if method == "DELETE":
            self.store.pop(rest, None)
            return {}
        raise AssertionError("metodo inesperado %s %s" % (method, path))


@pytest.fixture()
def vault(app, monkeypatch):
    fake = FakeVault()
    monkeypatch.setattr(sb, "_request", fake)
    sb.invalidate_token()
    yield fake
    sb.invalidate_token()


def configure(mode, **over):
    form = {"enabled": True, "mode": mode, "addr": "https://vault.test:8200",
            "mount": "satom", "auth": "approle", "role_id": "rid",
            "secret_id": "sid", "verify_tls": True, "timeout": 5}
    form.update(over)
    return sb.save(form)


def make_appliance(name="fw1", password="s3cr3t"):
    a = Appliance(name=name, kind="fortiweb", host="192.0.2.1", port=443,
                  username="admin")
    a.password = password
    db.session.add(a)
    db.session.commit()
    return a


# ---------------------------------------------------------------------------
# 1. el default no toca el vault
# ---------------------------------------------------------------------------
def test_default_mode_is_local_and_the_vault_is_never_contacted(app, monkeypatch):
    def explode(*a, **k):
        raise AssertionError("el vault fue contactado con la configuracion por defecto")

    monkeypatch.setattr(sb, "_request", explode)
    with app.app_context():
        assert sb.config()["mode"] == sb.MODE_LOCAL
        assert sb.active() is False
        assert sb.authoritative() is False
        a = make_appliance()
        assert a.password == "s3cr3t"
        assert sb.get_appliance_password("fw1") is None


def test_enabled_but_mode_local_still_never_contacts_the_vault(app, monkeypatch):
    """Encender el interruptor sin cambiar de modo NO puede mover secretos."""
    def explode(*a, **k):
        raise AssertionError("el vault fue contactado en modo local")

    with app.app_context():
        sb.save({"enabled": True, "mode": sb.MODE_LOCAL,
                 "addr": "https://vault.test:8200", "role_id": "rid",
                 "secret_id": "sid"})
        monkeypatch.setattr(sb, "_request", explode)
        a = make_appliance()
        assert a.password == "s3cr3t"


# ---------------------------------------------------------------------------
# 2. configuracion
# ---------------------------------------------------------------------------
def test_blank_secret_field_keeps_the_stored_credential(app, vault):
    with app.app_context():
        configure(sb.MODE_MIRROR)
        assert sb.config()["has_secret_id"] is True
        sb.save({"enabled": True, "mode": sb.MODE_MIRROR,
                 "addr": "https://vault.test:8200", "role_id": "rid",
                 "secret_id": ""})          # en blanco = conservar
        assert sb.config()["has_secret_id"] is True
        assert sb.config(reveal=True)["secret_id"] == "sid"


def test_config_never_echoes_the_secret_id(app, vault):
    with app.app_context():
        configure(sb.MODE_MIRROR)
        cfg = sb.config()
        assert cfg["secret_id"] == ""
        assert "sid" not in json.dumps(cfg)


def test_enabling_without_an_address_is_refused(app):
    with app.app_context():
        with pytest.raises(ValueError):
            sb.save({"enabled": True, "mode": sb.MODE_MIRROR, "addr": ""})


def test_an_unknown_mode_is_never_PERSISTED(app):
    """La validacion de ``save()`` y la normalizacion de ``config()`` son DOS
    reglas distintas, y hay que pinarlas por separado.

    Un aserto sobre ``config()`` no distingue una de otra: con la validacion de
    ``save()`` quitada sigue pasando, porque ``config()`` normaliza al leer. Este
    mira la FILA en bruto.
    """
    with app.app_context():
        sb.save({"enabled": True, "mode": "haz-lo-que-quieras",
                 "addr": "https://vault.test:8200"})
        raw = json.loads(AppSetting.get(sb.K_CONFIG))
        assert raw["mode"] == sb.MODE_LOCAL


def test_a_bad_mode_already_in_the_database_is_normalised_on_read(app):
    """La otra mitad: una fila escrita a mano o por una version anterior."""
    with app.app_context():
        sb.save({"enabled": True, "mode": sb.MODE_MIRROR,
                 "addr": "https://vault.test:8200"})
        raw = json.loads(AppSetting.get(sb.K_CONFIG))
        raw["mode"] = "modo-de-otra-version"
        AppSetting.set(sb.K_CONFIG, json.dumps(raw))
        assert sb.config()["mode"] == sb.MODE_LOCAL
        assert sb.active() is False


# ---------------------------------------------------------------------------
# 3. modo mirror
# ---------------------------------------------------------------------------
def test_mirror_writes_both_copies_and_reads_the_vault_first(app, vault):
    with app.app_context():
        configure(sb.MODE_MIRROR)
        a = make_appliance(password="original")
        assert vault.store["appliances/fw1"]["password"] == "original"
        # la copia local sigue siendo utilizable: eso es lo que hace reversible
        # el modo mirror
        assert encryption.decrypt(a.password_enc) == "original"

        vault.store["appliances/fw1"]["password"] = "cambiado-en-el-vault"
        assert a.password == "cambiado-en-el-vault"


def test_mirror_falls_back_to_local_when_the_vault_is_down(app, vault):
    with app.app_context():
        configure(sb.MODE_MIRROR)
        a = make_appliance(password="original")
        vault.fail_reads = True
        assert a.password == "original"


def test_mirror_falls_back_when_the_vault_simply_has_no_such_secret(app, vault):
    with app.app_context():
        configure(sb.MODE_MIRROR)
        a = make_appliance(password="original")
        vault.store.clear()
        assert a.password == "original"


# ---------------------------------------------------------------------------
# 4. modo vault (autoritativo) — aqui un fallo TIENE que romper
# ---------------------------------------------------------------------------
def test_vault_only_stores_a_sentinel_locally_not_the_password(app, vault):
    with app.app_context():
        configure(sb.MODE_VAULT)
        a = make_appliance(password="solo-en-el-vault")
        assert vault.store["appliances/fw1"]["password"] == "solo-en-el-vault"
        # el defecto que esto impide: dejar la contrasena vieja en la columna
        # local, donde sigue abriendo sesiones
        assert encryption.decrypt(a.password_enc) == sb.VAULT_SENTINEL
        assert a.password == "solo-en-el-vault"


def test_vault_only_raises_instead_of_returning_the_sentinel(app, vault):
    """Degradar aqui mandaria el literal '__stored-in-vault__' al aparato."""
    with app.app_context():
        configure(sb.MODE_VAULT)
        a = make_appliance(password="solo-en-el-vault")
        vault.fail_reads = True
        with pytest.raises(sb.VaultError):
            _ = a.password


def test_vault_only_raises_when_the_secret_is_missing(app, vault):
    with app.app_context():
        configure(sb.MODE_VAULT)
        a = make_appliance(password="solo-en-el-vault")
        vault.store.clear()
        with pytest.raises(sb.VaultError):
            _ = a.password


def test_vault_only_write_failure_does_not_silently_write_locally(app, vault, monkeypatch):
    with app.app_context():
        configure(sb.MODE_VAULT)
        monkeypatch.setattr(sb, "write", lambda *a, **k: (_ for _ in ()).throw(
            sb.VaultError("sin espacio")))
        a = Appliance(name="fw9", kind="fortiweb", host="192.0.2.9", port=443,
                      username="admin")
        with pytest.raises(sb.VaultError):
            a.password = "nunca-guardada"


# ---------------------------------------------------------------------------
# 5. la ruta ES el nombre
# ---------------------------------------------------------------------------
def test_an_unnamed_appliance_is_never_written_to_the_vault(app, vault):
    """Todas las filas sin nombre compartirian la ruta 'appliances/'."""
    with app.app_context():
        configure(sb.MODE_MIRROR)
        a = Appliance(name="", kind="fortiweb", host="192.0.2.2", port=443,
                      username="admin")
        a.password = "x"
        assert "appliances/" not in vault.store
        assert vault.store == {}
        assert encryption.decrypt(a.password_enc) == "x"


# ---------------------------------------------------------------------------
# 6. cache del token — un barrido de flota no puede abrir una sesion por equipo
# ---------------------------------------------------------------------------
def test_many_reads_share_one_login(app, vault):
    with app.app_context():
        configure(sb.MODE_MIRROR)
        for i in range(5):
            make_appliance(name="fw%d" % i, password="p%d" % i)
        sb.invalidate_token()
        vault.logins = 0
        for i in range(5):
            sb.get_appliance_password("fw%d" % i)
        assert vault.logins == 1


def test_a_credential_change_made_elsewhere_invalidates_the_cached_token(app, vault):
    """El caso real es OTRO worker de gunicorn, no el que guardo el formulario.

    ``save()`` llama a ``invalidate_token()``, pero eso solo limpia la cache del
    proceso que atendio el POST; los otros workers siguen con su token viejo.
    Por eso la cache lleva HUELLA de la credencial: el siguiente worker recalcula
    la huella desde la configuracion nueva de la BD, no casa, y vuelve a
    autenticar. Un test que llame a ``save()`` NO PUEDE ver ese defecto — pasa
    igual con la huella quitada, que es exactamente lo que midio la mutacion.
    """
    with app.app_context():
        configure(sb.MODE_MIRROR)
        make_appliance(password="p")
        sb.get_appliance_password("fw1")
        first = vault.logins

        # Un worker hermano cambia la credencial: la fila cambia y ESTA cache no
        # se entera por ningun otro medio.
        raw = json.loads(AppSetting.get(sb.K_CONFIG))
        raw["role_id"] = "rid-2"
        raw["secret_id_enc"] = encryption.encrypt("sid-2")
        AppSetting.set(sb.K_CONFIG, json.dumps(raw))

        sb.get_appliance_password("fw1")
        assert vault.logins == first + 1, (
            "se reutilizo un token minteado con la credencial ANTERIOR")


# ---------------------------------------------------------------------------
# 7. health
# ---------------------------------------------------------------------------
def test_health_reports_ok_when_everything_lines_up(app, vault):
    with app.app_context():
        configure(sb.MODE_MIRROR)
        h = sb.health()
        assert h["ok"] is True and h["mount_ok"] is True
        assert h["sealed"] is False


def test_health_never_raises_when_the_vault_is_unreachable(app, vault):
    with app.app_context():
        configure(sb.MODE_MIRROR)
        vault.fail_login = True
        h = sb.health()
        assert h["ok"] is False
        assert "authentication failed" in h["detail"].lower()


def test_health_says_sealed_instead_of_ok(app, vault, monkeypatch):
    """Un vault sellado responde — y no puede contestar por ningun secreto."""
    with app.app_context():
        configure(sb.MODE_MIRROR)

        def sealed(cfg, method, path, token="", body=None):
            if path == "sys/health":
                return {"sealed": True, "version": "2.6.2"}
            return vault(cfg, method, path, token, body)

        monkeypatch.setattr(sb, "_request", sealed)
        h = sb.health()
        assert h["ok"] is False and h["sealed"] is True


# ---------------------------------------------------------------------------
# 8. migracion
# ---------------------------------------------------------------------------
def test_dry_run_migration_writes_nothing(app, vault):
    with app.app_context():
        make_appliance(name="fw1", password="p1")
        make_appliance(name="fw2", password="p2")
        configure(sb.MODE_MIRROR)
        vault.store.clear()
        res = sb.migrate_local_to_vault(dry_run=True)
        assert res["dry_run"] is True and res["copied"] == 2
        assert vault.store == {}


def test_migration_verifies_by_reading_back(app, vault):
    with app.app_context():
        make_appliance(name="fw1", password="p1")
        configure(sb.MODE_MIRROR)
        vault.store.clear()
        res = sb.migrate_local_to_vault(dry_run=False)
        assert res["ok"] is True and res["copied"] == 1
        assert vault.store["appliances/fw1"]["password"] == "p1"


def test_a_write_that_stores_nothing_is_reported_as_failed(app, vault, monkeypatch):
    """200 OK y nada guardado es EL modo de fallo que la relectura existe para cazar."""
    with app.app_context():
        make_appliance(name="fw1", password="p1")
        configure(sb.MODE_MIRROR)
        vault.store.clear()
        monkeypatch.setattr(sb, "write", lambda path, data: None)   # traga y no guarda
        res = sb.migrate_local_to_vault(dry_run=False)
        assert res["ok"] is False and res["failed"] == 1


def test_migration_leaves_the_local_copies_alone(app, vault):
    with app.app_context():
        a = make_appliance(name="fw1", password="p1")
        enc_before = a.password_enc
        configure(sb.MODE_MIRROR)
        sb.migrate_local_to_vault(dry_run=False)
        assert Appliance.query.filter_by(name="fw1").first().password_enc == enc_before


def test_migration_refuses_when_the_vault_is_not_configured(app):
    with app.app_context():
        make_appliance()
        res = sb.migrate_local_to_vault(dry_run=True)
        assert res["ok"] is False and "not configured" in res["error"]


def test_already_vaulted_rows_are_skipped_not_recopied(app, vault):
    with app.app_context():
        configure(sb.MODE_VAULT)
        make_appliance(name="fw1", password="p1")
        res = sb.migrate_local_to_vault(dry_run=False)
        # Acotado al item del aparato: los dos secretos de directorio no estan
        # configurados en este test y tambien cuentan como "skipped", asi que
        # un aserto sobre el TOTAL pasaria aunque la fila se hubiera recopiado.
        row = [i for i in res["items"] if i["name"] == "fw1"][0]
        assert row["status"] == "skipped" and row["detail"] == "already vault-owned"
        assert res["copied"] == 0


# ---------------------------------------------------------------------------
# 9. el secreto compartido del FortiAuthenticator
# ---------------------------------------------------------------------------
def test_fortiauthenticator_secret_reads_from_the_vault_when_active(app, vault):
    from app.services import auth_store

    with app.app_context():
        AppSetting.set("auth.radius.secret_enc", encryption.encrypt("local-secret"))
        configure(sb.MODE_MIRROR)
        vault.store["auth/fortiauthenticator"] = {"shared_secret": "vault-secret"}
        cfg = auth_store.config(reveal_secrets=True)
        assert cfg["radius"]["secret"] == "vault-secret"


def test_fortiauthenticator_secret_falls_back_to_local_in_mirror(app, vault):
    from app.services import auth_store

    with app.app_context():
        AppSetting.set("auth.radius.secret_enc", encryption.encrypt("local-secret"))
        configure(sb.MODE_MIRROR)
        vault.fail_reads = True
        cfg = auth_store.config(reveal_secrets=True)
        assert cfg["radius"]["secret"] == "local-secret"


def test_fortiauthenticator_secret_raises_in_vault_only_mode(app, vault):
    from app.services import auth_store

    with app.app_context():
        AppSetting.set("auth.radius.secret_enc", encryption.encrypt("local-secret"))
        configure(sb.MODE_VAULT)
        vault.fail_reads = True
        with pytest.raises(sb.VaultError):
            auth_store.config(reveal_secrets=True)


def test_no_vault_means_auth_store_behaves_exactly_as_before(app, monkeypatch):
    from app.services import auth_store

    def explode(*a, **k):
        raise AssertionError("el vault fue contactado sin estar configurado")

    monkeypatch.setattr(sb, "_request", explode)
    with app.app_context():
        AppSetting.set("auth.radius.secret_enc", encryption.encrypt("local-secret"))
        cfg = auth_store.config(reveal_secrets=True)
        assert cfg["radius"]["secret"] == "local-secret"
