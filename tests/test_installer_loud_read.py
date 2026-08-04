"""[SATOM-LOUD-READ] Ningun prompt del instalador puede morir en silencio.

Encontrado ejecutando, no leyendo: conduciendo el instalador por tuberia con una
respuesta de menos, `read` recibio EOF, devolvio !=0 y `set -euo pipefail` mato
el script SIN IMPRIMIR NADA -- la ultima linea visible era el paso anterior.
Misma clase que [SATOM-LOUD-DB]. Ver docs/safeguards.md 10f.
"""
import pathlib
import re
import subprocess
import textwrap

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "installers" / "install-satom.sh"


def _executed_lines(text):
    """Lineas que se EJECUTAN: sin comentarios ni prosa."""
    return [
        s for s in (l.strip() for l in text.splitlines())
        if s and not s.startswith("#")
    ]


def _installer():
    return INSTALLER.read_text(encoding="utf-8")


def _extract(func, text):
    m = re.search(r"^%s\(\) \{.*?^\}$" % re.escape(func), text, re.M | re.S)
    assert m, "no se encontro la funcion %s()" % func
    return m.group(0)


# ---------------------------------------------------------------- estructural
def test_no_prompt_bypasses_the_loud_helpers():
    """Un `read` de prompt suelto vuelve a introducir la muerte muda.

    Este es el guardia que no envejece: al anadir un prompt nuevo el autor tiene
    que pasar por ask/ask_secret, o la suite cae. Comprobado sobre las lineas
    EJECUTADAS -- el comentario del propio helper habla de `read` y casaria.
    """
    raw = []
    for line in _executed_lines(_installer()):
        if not re.match(r"read -r[sp]", line):
            continue
        # Los dos `read` que viven DENTRO de ask/ask_secret son los legitimos.
        if '"$__p" "$__v"' in line:
            continue
        raw.append(line)
    assert not raw, "prompts que esquivan ask/ask_secret: %r" % raw


def test_every_prompt_goes_through_a_helper():
    """Y que efectivamente haya prompts (si no, el test anterior es vacuo)."""
    body = _installer()
    assert len(re.findall(r"^\s*ask ", body, re.M)) >= 8
    assert len(re.findall(r"^\s*ask_secret ", body, re.M)) >= 2


@pytest.mark.parametrize("func", ["ask", "ask_secret"])
def test_helper_reports_the_failure(func):
    """El helper tiene que DECIR cual prompt se quedo sin respuesta."""
    src = _extract(func, _installer())
    assert "_ask_die" in src, "%s() no reporta el fallo" % func
    assert "__rc" in src, "%s() no mira el codigo de salida de read" % func


def test_the_error_names_the_prompt():
    src = _extract("_ask_die", _installer())
    # OJO: en el shell va escapado (\\"$1\\"), asi que un aserto por la forma
    # entrecomillada NO casa. Que CITE el prompt lo prueba de verdad
    # test_eof_dies_loudly_not_silently, buscandolo en el stderr REAL.
    assert "$1" in src, "el mensaje no interpola el prompt que fallo"
    assert "die " in src, "_ask_die no aborta"


# ---------------------------------------------------------------- funcional
def _harness(tmp_path):
    """Monta un script con el codigo REAL del instalador, no con una copia."""
    body = _installer()
    h = tmp_path / "h.sh"
    h.write_text(
        "set -euo pipefail\n"
        "INSTALL_LOG=/dev/null; c_red=; c_off=\n"
        'die() { echo "ERROR: $*" >&2; exit 1; }\n'
        + _extract("_ask_die", body) + "\n"
        + _extract("ask", body) + "\n"
        + _extract("ask_secret", body) + "\n",
        encoding="utf-8",
    )
    return h


def _run(h, stdin, call):
    return subprocess.run(
        ["bash", "-c", "source %s; %s" % (h, call)],
        input=stdin, capture_output=True, text=True,
    )


@pytest.mark.parametrize("call", ["ask V 'P: '", "ask_secret V 'P: '"])
def test_eof_dies_loudly_not_silently(tmp_path, call):
    """EL BUG: entrada agotada -> rc!=0 y CERO salida. Ahora tiene que hablar."""
    r = _run(_harness(tmp_path), "", call)
    assert r.returncode != 0, "deberia abortar"
    assert r.stderr.strip(), "murio en silencio -- el bug esta de vuelta"
    assert "P: " in r.stderr, "no dice que prompt fue: %r" % r.stderr


def test_partial_line_without_newline_is_a_valid_answer(tmp_path):
    """Ctrl-D tras teclear: `read` devuelve !=0 pero SI hay respuesta."""
    r = _run(_harness(tmp_path), "parcial", "ask V 'P: '; echo GOT=$V")
    assert r.returncode == 0, r.stderr
    assert "GOT=parcial" in r.stdout


def test_normal_input_still_works(tmp_path):
    r = _run(_harness(tmp_path), "normal\n", "ask V 'P: '; echo GOT=$V")
    assert r.returncode == 0, r.stderr
    assert "GOT=normal" in r.stdout


def test_raw_read_is_the_silent_failure_we_are_preventing():
    """Ancla el comportamiento CONTRARIO: sin el helper, muere mudo.

    Sin esto, estrechar helper y test a la vez los dejaria auto-consistentes.
    """
    r = subprocess.run(
        ["bash", "-c", 'set -euo pipefail; read -rp "P: " V; echo GOT=$V'],
        input="", capture_output=True, text=True,
    )
    assert r.returncode != 0
    assert r.stderr.strip() == "", "premisa rota: el read crudo si hablaba"
