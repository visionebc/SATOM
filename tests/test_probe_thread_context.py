"""El badge de estado se sondea en HILOS, y un hilo no hereda el app context.

Lo que fija este fichero, en una linea: **"no puedo leer la configuracion del
vault" no es lo mismo que "el vault esta apagado"**, y confundir las dos cosas
marca offline a un aparato que responde.

El defecto real (medido 2026-09-14 contra la BD viva de satom-node-1): los tres
appliances del inventario (fac01, fortiweb15, fortiweb16) salian `offline` en
`GET /api/appliances` mientras el MISMO codigo, en el hilo principal, los daba
`online` en 0,08 s. La cadena:

1. `api/appliances.list_appliances` sonda dentro de un `ThreadPoolExecutor`.
2. Un hilo nuevo arranca con ContextVars vacias -> **sin app context**.
3. `secret_backend._raw()` hacia `AppSetting.get(...)` y se tragaba el fallo
   con `except Exception: return {}`.
4. Config vacia -> `active()` pasa a False -> `get_appliance_password()`
   devuelve None, que significa "usa la copia local".
5. La copia local es el centinela `__stored-in-vault__` -> el getter LANZA.
6. `probe_status` se traga la excepcion y devuelve `"offline"`.

Ninguna de las dos piezas introdujo el defecto por si sola: el pool existe
desde el commit inicial y era inofensivo porque el camino de la credencial era
env + columna (cero BD). Lo introdujo la COMBINACION, el dia que la credencial
paso a poder vivir en un vault (2026-08-19). Estuvo ~3,5 semanas en produccion
sin una linea de log, porque "offline" es una respuesta perfectamente creible.

Por eso los guardias de aqui son de DOS clases y hacen falta las dos:
  - de comportamiento: la ruta del badge tiene que decir `online`;
  - estructurales: `_raw()`/`active()` tienen que ROMPER en un hilo sin
    contexto en vez de contestar "apagado", porque si no el mismo sintoma
    reaparece en la proxima ruta que use hilos.
"""
import logging
import threading

import pytest
from flask import has_app_context

from app.models import Appliance, AppSetting, db
from app.services import encryption, secret_backend as sb

from conftest import admin_user_id, login
from test_secret_backend import configure, vault  # noqa: F401  (fixture)


VAULT_PW = "la-que-vive-solo-en-el-vault"


# ---------------------------------------------------------------------------
# doble de cliente
# ---------------------------------------------------------------------------
class _RecordingClient:
    """Cliente falso que EXIGE leer la credencial, como el de verdad.

    Un doble que no toque `appliance.password` haria pasar el guardia sin
    ejercitar la unica linea que rompe. Ademas apunta en QUE hilo corrio: es lo
    que distingue "arreglado" de "serializado en el hilo de la peticion", que
    tambien daria verde y convertiria la pagina en N x 6 s.
    """

    seen: list = []
    threads: set = set()

    def __init__(self, appliance, timeout=30.0):
        self.appliance = appliance

    def status_check(self):
        pw = self.appliance.password
        _RecordingClient.seen.append((self.appliance.name, pw))
        _RecordingClient.threads.add(threading.current_thread().name)
        return {"hostName": "FortiWeb", "version": "7.6.8"}


@pytest.fixture()
def rec(monkeypatch):
    _RecordingClient.seen = []
    _RecordingClient.threads = set()
    # client_for() y _own_client() acaban los dos aqui, asi que un solo parche
    # cubre la ruta del badge Y el boton de test manual.
    monkeypatch.setattr("app.clients.fortiweb.FortiWebClient", _RecordingClient)
    return _RecordingClient


def _vaulted_row(name="fortiweb16", host="192.0.2.28"):
    """Una fila como las que nacen con el vault ya autoritativo: sin copia local."""
    row = Appliance(name=name, kind="fortiweb", host=host, port=443,
                    username="admin",
                    password_enc=encryption.encrypt(sb.VAULT_SENTINEL))
    db.session.add(row)
    db.session.commit()
    return row


def _arm_vault(app, name="fortiweb16"):
    with app.app_context():
        configure(sb.MODE_VAULT)
        row = _vaulted_row(name)
        sb.write(sb.appliance_path(name), {"password": VAULT_PW})
        return row.id


# ---------------------------------------------------------------------------
# comportamiento: el defecto que vio el usuario
# ---------------------------------------------------------------------------
def test_the_badge_route_says_online_for_a_vault_backed_appliance(app, client, vault, rec):
    """El defecto reportado, tal cual: el aparato responde y el badge miente."""
    _arm_vault(app)
    login(client, admin_user_id(app))
    body = client.get("/api/appliances").get_json()
    assert [(a["name"], a["status"]) for a in body] == [("fortiweb16", "online")]


def test_the_probe_sends_the_vault_password_not_the_sentinel(app, client, vault, rec):
    """Verde no vale si llego con la credencial equivocada."""
    _arm_vault(app)
    login(client, admin_user_id(app))
    client.get("/api/appliances")
    assert rec.seen == [("fortiweb16", VAULT_PW)]
    assert all(sb.VAULT_SENTINEL not in pw for _, pw in rec.seen)


def test_every_appliance_is_probed_not_just_the_first(app, client, vault, rec):
    """El defecto afectaba a los TRES; un guardia de un solo equipo no lo ve."""
    with app.app_context():
        configure(sb.MODE_VAULT)
        for n in ("fac01", "fortiweb15", "fortiweb16"):
            _vaulted_row(n, host="192.0.2.1")
            sb.write(sb.appliance_path(n), {"password": VAULT_PW})
    login(client, admin_user_id(app))
    body = client.get("/api/appliances").get_json()
    assert {a["name"]: a["status"] for a in body} == {
        "fac01": "online", "fortiweb15": "online", "fortiweb16": "online"}


def test_the_probe_still_runs_off_the_request_thread(app, client, vault, rec):
    """Serializar en el hilo de la peticion tambien da verde, y es N x 6 s."""
    _arm_vault(app)
    login(client, admin_user_id(app))
    client.get("/api/appliances")
    assert rec.threads, "no se sondeo nada"
    assert threading.main_thread().name not in rec.threads


def test_the_cached_status_is_persisted(app, client, vault, rec):
    """Todas las demas vistas leen `last_status`, no vuelven a sondear."""
    rid = _arm_vault(app)
    login(client, admin_user_id(app))
    client.get("/api/appliances")
    with app.app_context():
        row = db.session.get(Appliance, rid)
        assert row.last_status == "online"
        assert row.last_checked_at is not None


# ---------------------------------------------------------------------------
# estructural: la degradacion silenciosa que lo causo
# ---------------------------------------------------------------------------
def test_the_vault_config_refuses_to_guess_without_an_app_context(app):
    """`{}` significaria "no configurado", y eso es una respuesta inventada."""
    assert not has_app_context(), "el guardia necesita correr FUERA de contexto"
    with pytest.raises(sb.VaultConfigUnavailable):
        sb._raw()


def test_active_does_not_answer_false_in_a_thread_without_context(app, vault):
    """Este es el paso 4 de la cadena: la mentira que se propaga."""
    with app.app_context():
        configure(sb.MODE_VAULT)
    box = {}

    def worker():
        try:
            box["value"] = sb.active()
        except BaseException as exc:  # noqa: BLE001 — se inspecciona abajo
            box["error"] = exc

    t = threading.Thread(target=worker)
    t.start()
    t.join()
    assert "value" not in box, (
        "el vault contesto %r desde un hilo sin contexto" % (box.get("value"),))
    assert isinstance(box["error"], sb.VaultConfigUnavailable)


def test_the_failure_is_not_a_kind_of_vault_error(app):
    """Si heredase de VaultError, `get_appliance_password` la volveria a tragar
    y devolveria None = "usa la copia local" — la degradacion, otra vez."""
    assert not issubclass(sb.VaultConfigUnavailable, sb.VaultError)


def test_an_unmigrated_settings_table_is_still_tolerated(app, monkeypatch):
    """Una instalacion nueva, antes de Alembic, NO tiene que romper."""
    def boom(*a, **k):
        raise RuntimeError("no such table: app_settings")

    with app.app_context():
        monkeypatch.setattr(AppSetting, "get", staticmethod(boom))
        assert sb._raw() == {}
        assert sb.active() is False


# ---------------------------------------------------------------------------
# el silencio de 3,5 semanas
# ---------------------------------------------------------------------------
def test_a_failed_probe_leaves_a_trace(app, caplog):
    """`offline` es creible, y por eso un fallo mudo sobrevive semanas."""
    with app.app_context():
        row = _vaulted_row("fortiweb15")  # centinela, vault fuera del camino
        with caplog.at_level(logging.WARNING):
            assert row.probe_status(timeout=0.1) == "offline"
    assert "fortiweb15" in caplog.text, "el aviso no dice CUAL fallo"


def test_a_probe_of_a_healthy_box_logs_nothing(app, vault, rec, caplog):
    """Un log por sondeo bueno convierte el aviso en ruido y nadie lo lee."""
    with app.app_context():
        configure(sb.MODE_VAULT)
        row = _vaulted_row()
        sb.write(sb.appliance_path("fortiweb16"), {"password": VAULT_PW})
        with caplog.at_level(logging.WARNING):
            assert row.probe_status(timeout=1.0) == "online"
    assert "fortiweb16" not in caplog.text


# ---------------------------------------------------------------------------
# un sondeo no es una edicion de configuracion
# ---------------------------------------------------------------------------
def test_a_status_poll_does_not_look_like_a_config_edit(app, client, vault, rec):
    """`updated_at` responde "cuando se edito esta fila", no "cuando se miro"."""
    rid = _arm_vault(app)
    with app.app_context():
        before = db.session.get(Appliance, rid).updated_at
    login(client, admin_user_id(app))
    client.get("/api/appliances")
    with app.app_context():
        row = db.session.get(Appliance, rid)
        assert row.updated_at == before
        assert row.last_checked_at is not None  # guarda-al-guardia: SI se sondeo


def test_the_manual_test_button_does_not_look_like_a_config_edit(app, client, vault, rec):
    """Mismo defecto, segunda ruta: el boton de la lista de appliances."""
    rid = _arm_vault(app)
    with app.app_context():
        before = db.session.get(Appliance, rid).updated_at
    login(client, admin_user_id(app))
    resp = client.post("/api/appliances/%d/test" % rid)
    assert resp.get_json()["status"] == "online"
    with app.app_context():
        row = db.session.get(Appliance, rid)
        assert row.updated_at == before
        assert row.last_status == "online"


class _DeadClient:
    """Falla con una excepcion ANONIMA: no nombra host, appliance ni credencial."""

    def __init__(self, appliance, timeout=30.0):
        pass

    def status_check(self):
        raise TimeoutError("timed out")


def _plain_row(name, host="192.0.2.27"):
    row = Appliance(name=name, kind="fortiweb", host=host, port=443,
                    username="admin", password_enc=encryption.encrypt("pw"))
    db.session.add(row)
    db.session.commit()
    return row


def test_the_trace_names_the_appliance_even_when_the_error_does_not(
        app, monkeypatch, caplog):
    """La trampa que dejo sobrevivir una mutacion en la primera pasada.

    `test_a_failed_probe_leaves_a_trace` usa el fallo del centinela, y ese
    RuntimeError YA lleva el nombre del appliance dentro. Asi que el aserto
    `"fortiweb15" in caplog.text` se cumplia por el texto de la EXCEPCION
    aunque el aviso no nombrara nada: quitar el `%s` del formato no rompia
    nada. Un timeout de red no nombra a nadie, y ahi si se ve.
    """
    monkeypatch.setattr("app.clients.fortiweb.FortiWebClient", _DeadClient)
    with app.app_context():
        _plain_row("fortiweb15")
        row = Appliance.query.filter_by(name="fortiweb15").one()
        with caplog.at_level(logging.WARNING):
            assert row.probe_status(timeout=0.1) == "offline"
    assert "fortiweb15" in caplog.text, "el aviso no dice CUAL fallo"
    assert "timed out" in caplog.text, "el aviso no dice POR QUE fallo"
