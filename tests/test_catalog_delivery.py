"""El catalogo compilado es un ARTEFACTO, y su entrega tiene que estar cubierta.

Contexto medido el 2026-08-10: los cuatro `.mo` viajaban en el repo y llevaban
identificadores internos reales -- `example.net` (x6), direcciones `10.0.0.x`
(x16), `hypervisor03` (x2), `backup-server` (x8-10). Eso dejaba al publicador entre dos
fallos:

* Sanear el binario (lo que hacia) reescribe bytes DENTRO del `.mo`, desplaza
  su tabla de offsets y el fichero publicado revienta al abrirlo. Una
  instalacion hecha desde el repo publico daba 500 en cada pagina en
  es/de/fr/it, y el publicador reportaba `RESULT: OK`.
* Saltarse el saneado para binarios publica la infraestructura interna.

La salida no es elegir el menos malo: es que un artefacto derivado no viaje. El
`.po` es texto, se sanea bien, y el `.mo` se genera donde se instala -- por eso
estas pruebas miran las DOS rutas de entrega (instalador y runner de update).
Sin ellas, "ya no versionamos el .mo" se convierte en "la interfaz esta en
ingles y nadie sabe por que".
"""
from __future__ import annotations

import pathlib
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "installers" / "install-satom.sh"
UPDATER = ROOT / "deploy" / "self_update_runner.py"
SHIPPED = ("es", "de", "fr", "it")


def _tracked() -> list[str]:
    out = subprocess.run(["git", "ls-files"], cwd=ROOT,
                         capture_output=True, text=True, timeout=60)
    return out.stdout.splitlines()


def test_no_compiled_catalogue_is_tracked_by_git():
    """El fallo concreto: cuatro binarios versionados que el saneado del
    publicador no puede tocar sin romperlos ni dejar sin tocar sin filtrar."""
    tracked = [p for p in _tracked() if p.endswith(".mo")]
    assert not tracked, (
        f"catalogos compilados versionados: {tracked}. Son derivados del .po; "
        "se generan en la instalacion (ver installers/install-satom.sh)"
    )


def test_the_source_catalogues_are_tracked():
    """La otra mitad. Sin `.po` versionado no hay nada de lo que derivar, y
    "no versionamos el .mo" se habria convertido en perder la traduccion."""
    tracked = set(_tracked())
    for code in SHIPPED:
        rel = f"app/translations/{code}/LC_MESSAGES/messages.po"
        assert rel in tracked, f"falta el catalogo fuente {rel}"


def test_the_installer_compiles_the_catalogues():
    """Una instalacion limpia clona el repo: sin este paso arranca sin ningun
    `.mo` y sirve la interfaz en ingles aunque el perfil pida otro idioma --
    en silencio, que es como se descubre un mes despues."""
    body = INSTALLER.read_text(encoding="utf-8")
    assert "pybabel compile" in body, (
        "el instalador no compila los catalogos; con el .mo fuera del repo "
        "eso deja toda instalacion nueva en ingles"
    )
    assert "app/translations" in body


def test_the_update_runner_compiles_the_catalogues():
    """Un update de codigo trae `.po` nuevos y ningun `.mo`."""
    body = UPDATER.read_text(encoding="utf-8")
    assert "pybabel" in body and "compile" in body, (
        "self_update_runner no recompila los catalogos tras traer codigo nuevo"
    )


def test_the_update_runner_compiles_even_without_a_pip_step():
    """Fuera del bloque ``do_pip``, a proposito: una actualizacion de solo
    codigo tambien trae catalogos nuevos."""
    body = UPDATER.read_text(encoding="utf-8")
    idx = body.index('pb = run([str(VENV / "pybabel")')
    before = body[:idx]
    # La ultima linea con indentacion de 8 espacios antes del compile marca el
    # nivel de bloque: si estuviera DENTRO de `if req.get("do_pip"...)` tendria
    # 12 espacios.
    line = body[idx - 8:idx]
    assert line == " " * 8, (
        "el paso de compilacion quedo anidado dentro de do_pip; un update de "
        "solo codigo no recompilaria"
    )
    assert 'if req.get("do_pip"' in before


def test_the_compile_step_never_aborts_the_update():
    """Un catalogo que no compila no puede tumbar una actualizacion: revertir
    un update por una traduccion es peor que la traduccion vieja."""
    body = UPDATER.read_text(encoding="utf-8")
    idx = body.index('pb = run([str(VENV / "pybabel")')
    window = body[idx:idx + 400]
    assert "raise" not in window, (
        "el paso de catalogos aborta el update; debe registrarse y seguir"
    )


@pytest.mark.parametrize("code", SHIPPED)
def test_the_catalogue_this_node_serves_is_compiled(code):
    """En un nodo VIVO el `.mo` tiene que existir aunque no este versionado.

    Se salta -- no falla -- en un checkout limpio: ahi su ausencia es correcta
    y quien la corrige es el instalador, cubierto por la prueba de arriba.
    """
    mo = ROOT / "app" / "translations" / code / "LC_MESSAGES" / "messages.mo"
    po = mo.with_suffix(".po")
    if not mo.exists():
        pytest.skip("checkout sin compilar: el instalador genera el .mo")
    assert mo.stat().st_mtime >= po.stat().st_mtime, (
        f"{code}: messages.mo mas viejo que su .po -- recompila"
    )


@pytest.mark.parametrize("code", SHIPPED)
def test_the_compiled_catalogue_is_ignored_by_git(code):
    """`.gitignore` cubriendolo es lo que impide que vuelva al indice en el
    proximo ``git add -A``."""
    rel = f"app/translations/{code}/LC_MESSAGES/messages.mo"
    out = subprocess.run(["git", "check-ignore", rel], cwd=ROOT,
                         capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, f"{rel} no esta cubierto por .gitignore"
