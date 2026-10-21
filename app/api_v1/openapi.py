"""/api/v1/openapi.json — the API described by the code that serves it.

The document is BUILT AT REQUEST TIME from three things the router already
holds: the rules of the ``api_v1`` blueprint (path, methods, path parameters),
the scope and capabilities stamped on each view by ``token_required`` /
``declares_capability`` (``app.api_v1.auth``), and each view's docstring
(first line = summary, the rest = description, an optional ``Responses:``
block = one line per status code). Nothing is kept in a second list: a route
added tomorrow is in the document the moment it is registered, and a view
without a docstring is a test failure (``tests/test_api_v1_openapi.py``), not
an undocumented endpoint.

It is served from the application, not generated into ``deploy/``: a file
there would be one more artefact to sign and one more copy to drift.

Scope and capabilities are vendor extensions (``x-satom-scope``,
``x-satom-capabilities``): OpenAPI's security model knows the bearer scheme,
not SATOM's owner-capped scope ladder.
"""
from __future__ import annotations

import inspect
import re

from flask import current_app, jsonify

from . import bp
from .auth import token_required

OPENAPI_VERSION = "3.0.3"

#: Werkzeug converter -> OpenAPI schema for a path parameter.
_CONVERTER_SCHEMA = {
    "int": {"type": "integer"},
    "float": {"type": "number"},
    "path": {"type": "string"},
    "string": {"type": "string"},
    "uuid": {"type": "string", "format": "uuid"},
    "any": {"type": "string"},
}

_RULE_PARAM = re.compile(r"<(?:(?P<conv>[a-z]+)(?:\([^)]*\))?:)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)>")
_RESPONSE_LINE = re.compile(r"^\s*(?P<code>[1-5]\d\d)\s*[:\-–]\s*(?P<text>.+?)\s*$")


def _openapi_path(rule) -> tuple[str, list[dict]]:
    """``/appliances/<int:id>`` -> ``/appliances/{id}`` + its parameters."""
    params = []

    def swap(m):
        conv = m.group("conv") or "string"
        name = m.group("name")
        params.append({
            "name": name, "in": "path", "required": True,
            "schema": dict(_CONVERTER_SCHEMA.get(conv, {"type": "string"})),
        })
        return "{%s}" % name

    path = _RULE_PARAM.sub(swap, str(rule))
    prefix = bp.url_prefix or ""
    if path.startswith(prefix):
        path = path[len(prefix):] or "/"
    return path, params


def _split_doc(doc: str) -> tuple[str, str, dict]:
    """(summary, description, responses) from a view docstring."""
    doc = inspect.cleandoc(doc or "")
    if not doc:
        return "", "", {}
    lines = doc.splitlines()
    summary = lines[0].strip()
    rest = lines[1:]
    responses: dict[str, str] = {}
    body: list[str] = []
    in_resp = False
    for line in rest:
        if line.strip().lower().rstrip(":") == "responses" and line.strip().endswith(":"):
            in_resp = True
            continue
        if in_resp:
            m = _RESPONSE_LINE.match(line)
            if m:
                responses[m.group("code")] = m.group("text")
                continue
            if line.strip():
                in_resp = False
            else:
                continue
        body.append(line)
    description = "\n".join(body).strip()
    return summary, description, responses


def _operation(rule, method: str, view) -> dict:
    summary, description, responses = _split_doc(view.__doc__)
    scope = getattr(view, "api_scope", None)
    caps = list(getattr(view, "api_capabilities", ()) or ())
    _path, params = _openapi_path(rule)
    op = {
        "operationId": rule.endpoint.split(".", 1)[-1] + "_" + method.lower(),
        "summary": summary,
        "security": [{"bearerAuth": []}],
        "x-satom-scope": scope,
        "x-satom-capabilities": caps,
        "responses": {},
    }
    if description:
        op["description"] = description
    if params:
        op["parameters"] = params
    if "200" not in responses and "201" not in responses and "202" not in responses:
        responses = dict({"200": "The call succeeded."}, **responses)
    responses.setdefault("401", "No token, or a token that is unknown, "
                                "revoked, expired or malformed.")
    if scope and scope != "read":
        responses.setdefault("403", "The scope, the owner's permission, the "
                                    "ADOM or a capability refused the call.")
    for code in sorted(responses):
        op["responses"][code] = {
            "description": responses[code],
            "content": {"application/json": {"schema": {"type": "object"}}},
        }
    return op


def build(app=None) -> dict:
    """The OpenAPI document of every ``api_v1`` rule the application serves."""
    app = app or current_app
    paths: dict[str, dict] = {}
    for rule in app.url_map.iter_rules():
        if rule.endpoint.split(".", 1)[0] != bp.name:
            continue
        view = app.view_functions.get(rule.endpoint)
        if view is None:
            continue
        path, _params = _openapi_path(rule)
        item = paths.setdefault(path, {})
        for method in sorted(rule.methods - {"HEAD", "OPTIONS"}):
            item[method.lower()] = _operation(rule, method, view)
    try:
        version = app.config.get("APP_VERSION") or _read_version()
    except Exception:  # noqa: BLE001 — a missing VERSION file is not a 500
        version = "0"
    return {
        "openapi": OPENAPI_VERSION,
        "info": {
            "title": "SATOM API v1",
            "version": version,
            "description": (
                "Token-authenticated integration surface. Every operation "
                "names the minimum token scope (x-satom-scope) and the "
                "explicit capabilities it asks for (x-satom-capabilities); "
                "a token never exceeds its owner's permissions or its ADOM. "
                "Prose manual: docs/api_v1.md."),
        },
        "servers": [{"url": bp.url_prefix or "/api/v1"}],
        "components": {
            "securitySchemes": {
                "bearerAuth": {"type": "http", "scheme": "bearer",
                               "bearerFormat": "fmk_<public_id>_<secret>"},
            },
        },
        "security": [{"bearerAuth": []}],
        "paths": dict(sorted(paths.items())),
    }


def _read_version() -> str:
    import pathlib
    root = pathlib.Path(__file__).resolve().parents[2]
    return (root / "VERSION").read_text(encoding="utf-8").strip()


@bp.route("/openapi.json", methods=["GET"])
@token_required("read")
def openapi_document():
    """The OpenAPI 3.0 document of this API, built from the live routes.

    Every path and method the blueprint serves, with its minimum scope and
    explicit capabilities as ``x-satom-*`` extensions. Built at request time:
    it cannot lag behind the code.

    Responses:
        200: The OpenAPI document (``application/json``).
    """
    return jsonify(build())
