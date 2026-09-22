"""Un control de formulario cuya unica clase no existe se pinta con los
defaults del navegador: sin borde SATOM, sin focus ring, y un <select> sin
'form-select' sale con el desplegable nativo del sistema operativo.

La pagina sigue devolviendo 200, ningun test de ruta se entera y nadie lo ve
hasta que un humano mira. Eso es exactamente como 'fw-input' -- una clase que
NO esta definida en ningun CSS -- sobrevivio 10 usos en console/index.html
desde 2026-06-27 hasta 2026-09-21.

Este guardia lee los <input>/<select>/<textarea> de TODAS las plantillas y
exige que al menos una de sus clases este definida en algun sitio real:
app/static/css/*.css, bootstrap vendorizado, o el <style> de su propia pagina.
"""
import re
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
TPL = ROOT / "app" / "templates"
CSS_DIR = ROOT / "app" / "static" / "css"
BOOTSTRAP = ROOT / "app" / "static" / "vendor" / "bootstrap" / "bootstrap.min.css"

CTRL = re.compile(r"<(input|select|textarea)\b[^>]*>", re.S)
SELECTOR = re.compile(r"\.([A-Za-z][A-Za-z0-9_-]+)")
STYLE_BLOCK = re.compile(r"<style[^>]*>(.*?)</style>", re.S)
CLASS_ATTR = re.compile(r'class="([^"]*)"')
# utilidades de espaciado/tamano: no aportan identidad visual, no cuentan
UTILITY = re.compile(
    r"(m|p)[tbxysel]?-\d|w-\d+|h-\d+|d-\w+|flex-\S+|text-\S+|font-\S+"
    r"|align-\S+|float-\S+|g-\d"
)

# Deuda congelada, medida 2026-09-21. El guardia es una carraca: anadir un
# control sin estilo FALLA, y arreglar uno de estos tambien falla (hay que
# borrarlo de la lista a proposito). No se anaden entradas sin leer el control.
KNOWN_UNSTYLED = {
    ("exceptions/list.html", "det-pick"),
    ("faz/section.html", "fazdev-sel"),
    ("plugins/editor.html", "ds-cb"),
    ("plugins/editor.html", "pb-required"),
    ("workspace/_fields.html", "input_cls fw-toggle"),
    ("workspace/policies.html", "fw-pol-check"),
    ("workspace/policy_detail.html", "fw-cr-default fw-toggle"),
}


def _global_selectors():
    text = "".join(p.read_text(errors="ignore") for p in sorted(CSS_DIR.glob("*.css")))
    text += BOOTSTRAP.read_text(errors="ignore")
    return set(SELECTOR.findall(text))


def _offenders():
    known_global = _global_selectors()
    out = set()
    for path in sorted(TPL.rglob("*.html")):
        raw = path.read_text(errors="ignore")
        local = set(SELECTOR.findall("".join(STYLE_BLOCK.findall(raw))))
        known = known_global | local
        for match in CTRL.finditer(raw):
            tag = match.group(0)
            if 'type="hidden"' in tag:
                continue
            attr = CLASS_ATTR.search(tag)
            if not attr:
                continue
            # un token con Jinja dentro no se puede resolver estaticamente
            classes = [c for c in attr.group(1).split() if "{" not in c and "}" not in c]
            meaningful = [c for c in classes if not UTILITY.fullmatch(c)]
            if meaningful and not any(c in known for c in meaningful):
                rel = path.relative_to(TPL).as_posix()
                out.add((rel, " ".join(meaningful)))
    return out


def test_bootstrap_and_css_are_readable():
    # si el CSS no se lee, todo saldria 'sin estilo' y el guardia mordería por
    # la razon equivocada -- o peor, la lista congelada lo taparia
    assert BOOTSTRAP.exists(), BOOTSTRAP
    assert len(_global_selectors()) > 500


def test_no_new_unstyled_form_controls():
    found = _offenders()
    nuevos = found - KNOWN_UNSTYLED
    assert not nuevos, (
        "controles de formulario cuya unica clase no existe en ningun CSS "
        "(se pintan con los defaults del navegador): " + repr(sorted(nuevos))
    )


def test_frozen_list_has_not_silently_grown():
    found = _offenders()
    arreglados = KNOWN_UNSTYLED - found
    assert not arreglados, (
        "estos ya estan arreglados: borralos de KNOWN_UNSTYLED para que la "
        "carraca no permita reintroducirlos: " + repr(sorted(arreglados))
    )


def test_console_page_uses_house_form_classes():
    raw = (TPL / "console" / "index.html").read_text()
    assert "fw-input" not in raw, "fw-input no existe en ningun CSS"
    assert raw.count("form-select fw-form-control") == 2, "los 2 <select>"
    assert raw.count("form-control fw-form-control") == 8, "inputs + textareas"
    for match in CTRL.finditer(raw):
        tag = match.group(0)
        if 'type="hidden"' in tag or "form-check-input" in tag:
            continue
        attr = CLASS_ATTR.search(tag)
        assert attr, tag[:80]
        assert "fw-form-control" in attr.group(1), tag[:80]
