"""Guardias de los dos defectos del 2026-08-10 (perfil + plataforma por defecto).

Ninguno de los dos rompia nada. Los dos simplemente AFIRMABAN algo falso, que
es la clase de fallo que ningun test cazaba:

* La tarjeta "About" del perfil anunciaba ``v1.0`` -- correcto durante
  exactamente un release, y llevaba ocho equivocado. Existia un guardia
  (``test_no_version_literal_in_the_templates_that_display_one``) pero recorria
  una LISTA ENUMERADA de dos plantillas, y ``auth/profile.html`` nunca estuvo
  en ella. Un allowlist enumerado sobre un arbol que crece es un guardia que
  deja de cubrir sin avisar; aqui se invierte -- se barren TODAS y hay que dar
  motivo para excluir.
* El selector de plataforma por defecto ofrecia tres opciones de un roster de
  cuatro familias, y su whitelist server-side plegaba EN SILENCIO cualquier
  otra a FortiWeb. Elegir FortiAuthenticator se guardaba como FortiWeb sin un
  solo mensaje de error.
"""
from __future__ import annotations

import pathlib
import re

import pytest

from tests.conftest import admin_user_id, login

ROOT = pathlib.Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "app" / "templates"
VERSION_LITERAL = re.compile(r"\bv\d+\.\d+(?:\.\d+)?\b")

#: Plantillas donde un literal ``vN.M`` NO es la version de la aplicacion.
#: Excluir exige motivo: es lo que impide que esta lista se convierta en el
#: mismo allowlist enumerado que dejo pasar el ``v1.0`` del perfil.
VERSION_LITERAL_EXEMPT = {
    "api_explorer/index.html": "v2.0 es la version del API del appliance, no la nuestra",
    "exceptions/index.html": "v2.0 es la version del API del appliance",
    "registry/index.html": "v2.0 es la version del API del appliance",
    "scheduled_actions/form.html": "v2.0 es la version del API del appliance",
    "registry/versions.html": "v2.0 es la version del API del appliance; "
                              "la pagina ENTERA trata de eso",
}

#: Un comentario Jinja se borra en el servidor y no llega a ningun navegador.
JINJA_COMMENT = re.compile(r"\{#.*?#\}", re.S)


def _strip_jinja_comments(text: str) -> str:
    """El texto que un operador puede llegar a ver.

    Sin este filtro el guardia se contesta con la prosa que lo explica:
    change_requests/detail.html documenta en un comentario la tarjeta "that
    claimed v1.0 for eight releases" -- el defecto historico que este mismo
    test persigue. Marcarlo como infraccion obliga a exentar el fichero
    entero, y entonces un literal DE VERDAD entra ahi sin vigilancia.

    No greedy: dos comentarios en una linea no pueden tragarse lo de enmedio.
    """
    return JINJA_COMMENT.sub("", text)


def _live_templates() -> list[pathlib.Path]:
    return [p for p in sorted(TEMPLATES.rglob("*.html"))
            if ".bak" not in p.name and ".pre-" not in p.name]


# --------------------------------------------------------------------------
# La version: ninguna plantilla la escribe a mano
# --------------------------------------------------------------------------

def test_no_template_anywhere_hardcodes_the_application_version():
    """Barre el arbol ENTERO, no una lista escrita a mano.

    El guardia anterior nombraba base.html y settings/index.html. El literal
    vivia en auth/profile.html.
    """
    offenders = {}
    for path in _live_templates():
        rel = path.relative_to(TEMPLATES).as_posix()
        if rel in VERSION_LITERAL_EXEMPT:
            continue
        found = VERSION_LITERAL.findall(
            _strip_jinja_comments(path.read_text(encoding="utf-8")))
        if found:
            offenders[rel] = found
    assert not offenders, (
        f"literal de version en {offenders}; usa {{{{ app_version }}}} "
        "(app/version.py), o documenta la excepcion en VERSION_LITERAL_EXEMPT"
    )


def test_the_exemption_list_has_no_dead_entries():
    """Una excepcion que ya no aplica es una puerta abierta sin vigilancia."""
    dead = [rel for rel in VERSION_LITERAL_EXEMPT
            if not (TEMPLATES / rel).is_file()
            or not VERSION_LITERAL.search(_strip_jinja_comments(
                (TEMPLATES / rel).read_text(encoding="utf-8")))]
    assert not dead, f"excepciones que ya no hacen falta: {dead}"


def test_a_version_literal_in_a_jinja_comment_is_not_an_offender():
    """Nunca se renderiza, asi que no puede enganar a nadie."""
    assert not VERSION_LITERAL.findall(
        _strip_jinja_comments("{# the card that claimed v1.0 for releases #}"))


def test_a_version_literal_outside_a_comment_is_still_an_offender():
    """El filtro no puede ser una puerta trasera."""
    assert VERSION_LITERAL.findall(
        _strip_jinja_comments("<b>v1.0</b>{# esto si es un comentario #}"))


def test_stripping_does_not_swallow_what_sits_between_two_comments():
    """Un ``.*`` codicioso se comeria el literal de enmedio y daria verde."""
    assert VERSION_LITERAL.findall(
        _strip_jinja_comments("{# a #}<b>v9.9</b>{# b #}")) == ["v9.9"]


def test_the_profile_about_card_interpolates_the_version(app, client):
    """La superficie concreta que estaba mal, renderizada de verdad."""
    from app.version import app_version

    login(client, admin_user_id(app), product="global")
    body = client.get("/auth/profile", follow_redirects=True).get_data(as_text=True)
    assert f"v{app_version()}" in body, "la tarjeta About no muestra la version viva"


# --------------------------------------------------------------------------
# La tarjeta About no puede anunciar una sola familia
# --------------------------------------------------------------------------

@pytest.mark.parametrize("claim", [
    "API Target",
    "FortiWeb 7.6 REST API",
    "Custom FortiWeb 7.6 Theme",
    "FortiWeb &amp; FortiADC management console",
])
def test_the_about_card_makes_no_single_family_claim(claim):
    """SATOM enruta CUATRO clientes (app/models.py). Anunciar la API de una
    sola familia no era incompleto: era falso."""
    text = (TEMPLATES / "auth" / "profile.html").read_text(encoding="utf-8")
    assert claim not in text, f"la tarjeta About sigue afirmando {claim!r}"


# --------------------------------------------------------------------------
# El roster de plataformas tiene UN autor
# --------------------------------------------------------------------------

def test_the_settings_template_does_not_carry_its_own_platform_list():
    """Dos autores de una lista es como se quedo sin FortiAuthenticator.

    Se mira solo el bloque del ``<select name="default_kind">``: el resto de la
    pagina nombra plataformas legitimamente (etiquetas, ayudas, otras tablas).
    """
    text = (TEMPLATES / "settings" / "index.html").read_text(encoding="utf-8")
    block = re.search(r'<select name="default_kind".*?</select>', text, re.S)
    assert block, "desaparecio el selector de plataforma por defecto"
    body = block.group(0)
    hardcoded = re.findall(r'<option value="(?!\{\{)([^"]+)"', body)
    assert not hardcoded, (
        f"opciones escritas a mano {hardcoded}; el roster sale de "
        "product_scope.device_products()"
    )


def test_every_family_the_product_routes_is_offered(app):
    """El roster del selector = el roster del producto. Sin resta."""
    from app.services import product_scope

    keys = {k for k, _ in product_scope.device_products()}
    assert {"fortiweb", "fortiadc", "fortiauthenticator", "fortianalyzer"} <= keys


def test_the_server_accepts_every_family_in_the_roster(app):
    """La plantilla es una pista; ESTO es la regla.

    Con la whitelist a mano, ``fortiauthenticator`` se guardaba como
    ``fortiweb`` sin un mensaje de error: el operador elegia una cosa y el
    sistema guardaba otra.
    """
    from app.services import product_scope, settings_store

    for key, _ in product_scope.device_products():
        assert settings_store.normalise_default_kind(key) == key, (
            f"el guardia server-side no acepta {key!r}, que SI esta en el roster"
        )


@pytest.mark.parametrize("posted", ["", None, "fortiswitch", "../../etc/passwd", "FortiWeb-Cloud"])
def test_a_value_outside_the_roster_never_survives(app, posted):
    """Un ``default_kind`` posteado a mano no puede aterrizar tal cual."""
    from app.services import product_scope, settings_store

    got = settings_store.normalise_default_kind(posted)
    assert got in {k for k, _ in product_scope.device_products()}


@pytest.mark.parametrize("legacy,expected", [
    ("FortiWeb", "fortiweb"),
    ("FortiADC", "fortiadc"),
    ("FortiWeb-Cloud", "fortiweb"),
])
def test_the_values_stored_before_the_roster_still_read_back(app, legacy, expected):
    """Sin la migracion, una instalacion vieja abre la pagina con NINGUNA
    opcion marcada y el operador lee que su ajuste se perdio."""
    from app.services import settings_store

    assert settings_store.normalise_default_kind(legacy) == expected


def test_the_save_path_itself_rejects_a_value_outside_the_roster(app):
    """El CAMINO DE ESCRITURA, no el ayudante.

    Esta prueba existe porque una mutacion la exigio: devolviendo
    ``save_general`` a su whitelist de tres valores escrita a mano, todos los
    demas guardias de este fichero seguian verdes -- comprobaban
    ``normalise_default_kind`` en aislamiento y nadie comprobaba que el que
    ESCRIBE lo use. Era exactamente el bug reportado, y el guardia no lo veia.
    """
    from app.services import settings_store as ss

    with app.app_context():
        for key, _ in ss.platform_choices():
            ss.save_general(app_name="SATOM", default_kind=key, session_timeout=60,
                            poll_interval=30, show_raw_config=False, log_levels=["INFO"])
            assert ss.general()["default_kind"] == key, (
                f"guardar {key!r} no lo conserva: el camino de escritura no "
                "pasa por el roster"
            )

        # Y un valor de fuera no puede aterrizar tal cual.
        ss.save_general(app_name="SATOM", default_kind="fortiswitch", session_timeout=60,
                        poll_interval=30, show_raw_config=False, log_levels=["INFO"])
        got = ss.general()["default_kind"]
        assert got in {k for k, _ in ss.platform_choices()}, got


def test_the_default_platform_is_actually_preselected(app, client):
    """El texto de ayuda promete "Pre-selected when registering a new
    appliance". Hasta hoy NADIE leia el ajuste: se escribia y se mostraba, y el
    formulario de alta lo ignoraba. Un ajuste cuya ayuda miente es peor que un
    ajuste que no existe."""
    from app.services import settings_store

    # Global: un ADOM concreto solo puede crear SU familia, asi que el
    # selector traeria una sola opcion y la prueba no diria nada.
    login(client, admin_user_id(app), product="global")
    with app.app_context():
        want = settings_store.general().get("default_kind")
    body = client.get("/appliances/", follow_redirects=True).get_data(as_text=True)
    block = re.search(r'<select class="form-select fw-form-control" name="kind".*?</select>',
                      body, re.S)
    assert block, "no se encontro el selector de plataforma del alta"
    selected = re.findall(r'value="([^"]+)"\s+selected', block.group(0))
    assert selected == [want], f"preseleccionada {selected}, esperada [{want!r}]"
