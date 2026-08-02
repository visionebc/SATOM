"""Los scripts de deploy no pueden depender del entorno de una distro.

Estas unidades corren fuera de la aplicacion, como la cuenta de servicio, en
cualquier distribucion soportada. Dos veces ya se han roto EN SILENCIO por
asumir el entorno de Debian:

  2026-07-27  `runuser` solo funciona como root. Al bajar las unidades a la
              cuenta de servicio, scheduler_guard y git-publish dejaron de
              funcionar y systemd siguio mostrando SUCCESS.
  2026-08-02  `python3` no existe en openSUSE (el binario es python3.11). El
              descubrimiento de peer del datasync devolvia vacio, el script
              lo trataba como "no hay peer" y salia con exit 0: la unidad en
              verde y data/ sin replicar.

La regla: si un script de deploy necesita Python, usa el del venv de la
aplicacion. Existe siempre en un nodo instalado y tiene la version correcta.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

DEPLOY = Path(__file__).resolve().parent.parent / "deploy"

# Scripts que NO corren en un nodo ya instalado (no hay venv todavia) o que
# son legado explicito. Cada exencion tiene que justificarse aqui.
EXEMPT = {
    "install.sh",  # bootstrap legado: corre ANTES de que exista el venv
}

SHELL_SCRIPTS = sorted(p for p in DEPLOY.glob("*.sh") if p.name not in EXEMPT)

BARE_PYTHON = re.compile(r"(?<![\w/.\-])(?:python3(?:\.\d+)?|python)\b(?![\w.\-])")


def code_lines(path: Path):
    """Lineas de CODIGO: sin vacias y sin comentarios.

    Es esencial. La primera version de este fichero no lo hacia y marcaba tres
    scripts que solo mencionan `runuser` en un comentario explicando por que NO
    lo usan. Un test que casa prosa no prueba nada.
    """
    for n, raw in enumerate(path.read_text().splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        yield n, raw


def code_text(path: Path) -> str:
    return "\n".join(raw for _, raw in code_lines(path))


@pytest.mark.parametrize("script", SHELL_SCRIPTS, ids=lambda p: p.name)
def test_deploy_scripts_do_not_call_a_bare_python(script: Path) -> None:
    offenders = []
    for n, raw in code_lines(script):
        cleaned = raw.replace("venv/bin/python", "OKPY")
        for m in BARE_PYTHON.finditer(cleaned):
            before = cleaned[: m.start()].rstrip()
            if before and not before.endswith(("|", "(", "&&", "||", "=", ";", "$")):
                continue
            offenders.append("%s:%d: %s" % (script.name, n, raw.strip()))
    assert not offenders, (
        "Un script de deploy invoca un Python de la distro. En openSUSE no "
        'existe /usr/bin/python3 y el fallo es SILENCIOSO. Usa "$APP/venv/bin/python".\n  '
        + "\n  ".join(offenders)
    )


@pytest.mark.parametrize("script", SHELL_SCRIPTS, ids=lambda p: p.name)
def test_deploy_scripts_do_not_call_runuser_without_a_root_guard(script: Path) -> None:
    """`runuser` solo funciona como root. Un script que la INVOCA tiene que
    ramificar por `id -u` o declarar que exige root."""
    text = code_text(script)
    if not re.search(r"(?<![\w/.\-])runuser\b", text):
        pytest.skip("no invoca runuser")
    guarded = ("id -u" in text) or ("EUID" in text)
    assert guarded, (
        "%s invoca runuser sin comprobar que corre como root. Las unidades "
        "bajaron a la cuenta de servicio el 2026-07-26 y runuser solo "
        "funciona como root." % script.name
    )


def test_the_datasync_peer_probe_fails_loudly() -> None:
    """Una sonda que no puede evaluarse NO puede parecer 'no hay nada que
    hacer'. Ese era el modo de fallo exacto: unidad en verde, data/ sin
    replicar."""
    text = (DEPLOY / "satom-ha-datasync.sh").read_text()
    assert "PEER_RC" in text, "el codigo de salida de la sonda de peer se descarta"

    tail = text[text.index("PEER_RC"):]
    assert re.search(r'"\$PEER_RC"\s*-ne\s*0', tail), (
        "el codigo de salida de la sonda de peer no se comprueba"
    )
    # El bloque que trata el fallo tiene que salir != 0. Se mira la rama, no
    # el fichero entero: `exit 1` en cualquier otro sitio no prueba nada.
    branch = tail[tail.index("-ne"): tail.index("-ne") + 400]
    assert "exit 1" in branch, "un fallo de la sonda de peer no sale distinto de cero"

    # Y el caso legitimo (no hay peer) tiene que seguir siendo exit 0, para no
    # convertir un standalone en una alerta permanente.
    assert re.search(r'if \[ -z "\$\{PEER\}" \]', text), (
        "se perdio la distincion entre 'sin peer configurado' y 'sonda rota'"
    )
