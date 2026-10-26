"""/api/v1/builder -- what SATOM Builder calls (contract ``satom-api`` §1).

SATOM Builder is a separate, customer-installed tool that builds plugins and
Plugin Studio apps. Each author links their OWN token, so every call here
runs with that person's RBAC and ADOM, and SATOM stays the authority:

* ``GET /builder/target`` -- this server described for the rules (§2);
* ``GET /builder/rules-pack`` -- SATOM's own rule code, as a zip (§3), with
  the runtime the Builder tests on test data with (§13);
* ``GET /builder/library[/fortinet/<product>/<version>]`` -- structure a
  plugin builds on: datasets, stores, API Catalog, API library (§14);
* ``GET /builder/data`` -- this server's rows for the Builder's test data:
  datasets as a render here shows the owner, data stores, ``satom_select``
  lists; the owner must be a Plugin Studio author (§15);
* ``POST /builder/validate`` -- ``package_check.check`` with the ``builder``
  policy; nothing is written (§4);
* ``POST /builder/rehearse`` -- an unarmed walk of the package's app against
  this server's objects, or a sandbox render of a view (§5). The owner must
  be a Plugin Studio author (``studio.script_library``);
* ``POST /builder/import`` -- the console's import path
  (``services.plugin_import``), ``builder`` policy for an unsigned package;
  ``admin`` scope and a super-admin owner (``studio.plugin_studio``) (§6);
* ``GET/POST /builder/publishers`` -- the trusted publisher keys (§8).

Every call but the rules pack and the publishers takes ``?adom=<key>``
(contract §17): with a Global token it is the ADOM the call runs in, among
Global and the ADOMs the owner may enter; a token bound to an ADOM can only
name its own. The library and the target say what the token reaches
(``reach``) and which datasets live in the owner's other ADOMs
(``elsewhere``).

Package bodies are multipart: ``package`` (at most 10 MB, else 413) and an
optional ``options`` JSON string. Every call writes one audit line naming
the token and its owner; a secret relayed by ``import`` is never in it.
"""
from __future__ import annotations

import json
from contextlib import contextmanager

from flask import g, jsonify, make_response, request

from ..extensions import limiter
from ..services import plugin_package as P
from ..services.audit import log_action
from . import bp
from .auth import audit_extra, token_required

#: Multipart framing and the ``options`` field on top of the package itself.
_ENVELOPE = 256 * 1024
SUPER_ADMIN = "studio.plugin_studio"
GLOBAL = "global"


def _err(status: int, code: str, message: str, **extra):
    body = {"error": code, "message": message}
    body.update(extra)
    return jsonify(body), status


def _owner():
    return getattr(g, "api_token_owner", None)


def _product() -> str:
    return getattr(g, "product", "") or ""


@contextmanager
def _as_owner():
    """``current_user`` is the token's owner for the call: ADOM stamping,
    the datasets a render may show and the audit line all follow the human
    behind the token, never an anonymous request."""
    had = "_login_user" in g
    before = g.get("_login_user")
    g._login_user = _owner()
    try:
        yield
    finally:
        if had:
            g._login_user = before
        else:
            g.pop("_login_user", None)


def _token_adom() -> str:
    """The ADOM the token itself is bound to: ``global`` for a Global token."""
    tok = getattr(g, "api_token", None)
    return ((getattr(tok, "product", "") or "").strip().lower() or GLOBAL) if tok else GLOBAL


def _adom_refusal():
    """A token's ADOM the owner may no longer enter is refused (403).

    Contract §17: ``?adom=<key>`` names the ADOM of this call. A Global token
    may name Global or any ADOM its owner may enter, and the whole call --
    datasets, snapshot, check, render, import -- then runs in it (``g.product``,
    which ``product_scope`` reads first). A token bound to an ADOM may only
    name that ADOM: it never widens."""
    from ..services import product_scope as PSc
    owner = _owner()
    allowed = getattr(owner, "allowed_adoms", None)
    if allowed is not None:
        allowed = {str(k).strip().lower() for k in allowed}
    product = _product()
    if allowed is not None and product and product != GLOBAL and product not in allowed:
        return _err(403, "wrong_product",
                    "The token's owner may not work in the ADOM this token is bound to.")
    want = (request.args.get("adom") or "").strip().lower()
    if not want:
        return None
    if want not in PSc.product_keys():
        return _err(400, "bad_request", "Unknown ADOM %r." % want[:40])
    tok = _token_adom()
    if tok != GLOBAL and want != tok:
        return _err(403, "wrong_product",
                    "This token is bound to ADOM %s; only a Global token chooses the ADOM "
                    "of a call." % tok)
    if want != GLOBAL and allowed is not None and want not in allowed:
        return _err(403, "wrong_product", "The token's owner may not work in ADOM %s." % want)
    g.product = want
    return None


def _package():
    """``(bytes, options, None)`` or ``(None, None, error response)``."""
    n = request.content_length
    if n is not None and n > P.MAX_PACKAGE + _ENVELOPE:
        return None, None, _err(413, "too_large", "The package is larger than %d MB."
                                % (P.MAX_PACKAGE // 1048576))
    up = request.files.get("package")
    if up is None:
        return None, None, _err(400, "bad_request",
                                "Send the package as the multipart field 'package'.")
    data = up.read(P.MAX_PACKAGE + 1)
    if len(data) > P.MAX_PACKAGE:
        return None, None, _err(413, "too_large", "The package is larger than %d MB."
                                % (P.MAX_PACKAGE // 1048576))
    raw = request.form.get("options") or ""
    try:
        options = json.loads(raw) if raw.strip() else {}
    except ValueError:
        options = None
    if not isinstance(options, dict):
        return None, None, _err(400, "bad_request", "'options' must be a JSON object.")
    return data, options, None


def _audit(action: str, target: str = "", **more):
    log_action(action, target=target, extra=audit_extra(**more))


@bp.route("/builder/target", methods=["GET"])
@token_required("read")
def builder_target():
    """This server described for SATOM Builder: version, choices, objects, schema.

    The answer is the ``target`` the rules pack's ``check()`` takes, unchanged:
    picker values, Examples templates, the Studio objects that exist (never a
    secret: only whether a connection has one), the enabled publishers of the
    token's ADOM and the schema computed from all of that.

    Responses:
        200: The target snapshot (``satom.builder-target/1``).
        403: The owner may not work in the token's ADOM (``wrong_product``).
    """
    from ..services import builder_target as BT
    refused = _adom_refusal()
    if refused:
        return refused
    with _as_owner():
        snap = BT.snapshot(_owner(), _product(), scopes=g.api_token.scope_list,
                           token_adom=_token_adom())
        _audit("builder.target", target=_product())
    return jsonify(snap)


@bp.route("/builder/rules-pack", methods=["GET"])
@token_required("read")
def builder_rules_pack():
    """The rules pack: SATOM's own package rules as a zip, for local checks.

    ``application/zip``, named ``satom-rules-<version>-<sha12>.zip``; the
    header ``X-Satom-Rules-Sha256`` carries the zip's SHA-256.

    Responses:
        200: The zip.
    """
    from ..services import rules_pack
    from ..version import app_version
    data, sha = rules_pack.build()
    with _as_owner():
        _audit("builder.rules_pack", target=sha[:12])
    resp = make_response(data)
    resp.headers["Content-Type"] = "application/zip"
    resp.headers["Content-Disposition"] = 'attachment; filename="satom-rules-%s-%s.zip"' % (
        app_version(), sha[:12])
    resp.headers["X-Satom-Rules-Sha256"] = sha
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp


@bp.route("/builder/library", methods=["GET"])
@token_required("read")
def builder_library():
    """What a plugin can build on, structure only (contract §14).

    The datasets with their columns, the data stores with their column
    definitions, the API Catalog with every version's endpoints, and the
    builds the API library knows for the token's ADOM. Never a row of data,
    never a secret.

    Responses:
        200: ``satom.builder-library/1``.
        403: The owner may not work in the token's ADOM (``wrong_product``).
    """
    from ..services import builder_library as BL
    refused = _adom_refusal()
    if refused:
        return refused
    with _as_owner():
        res = BL.library(_product(), owner=_owner(), token_adom=_token_adom())
        _audit("builder.library", target=_product())
    return jsonify(res)


@bp.route("/builder/library/fortinet/<product>/<version>", methods=["GET"])
@token_required("read")
def builder_library_build(product, version):
    """One build of the API library: its endpoints, or with ``?endpoint=``
    that endpoint's fields (contract §14).

    Responses:
        200: ``{"product", "version", "endpoints": [...]}`` or
             ``{"product", "version", "endpoint", "status", "fields"}``.
        400: The version or endpoint is malformed (``bad_request``).
        403: The product is not the token's ADOM (``wrong_product``).
    """
    import re
    from ..services import builder_library as BL
    refused = _adom_refusal()
    if refused:
        return refused
    if product not in BL.products_for(_product(), _owner()):
        return _err(403, "wrong_product", "The token's ADOM does not cover %s." % product[:40])
    endpoint = request.args.get("endpoint") or ""
    if not re.match(r"^[0-9A-Za-z._-]{1,40}$", version) or len(endpoint) > 200:
        return _err(400, "bad_request", "Malformed version or endpoint.")
    with _as_owner():
        if endpoint:
            res = BL.fortinet_fields(product, version, endpoint)
        else:
            res = BL.fortinet_endpoints(product, version)
        _audit("builder.library.build", target="%s %s" % (product, version),
               endpoint=endpoint[:120])
    return jsonify(res)


@bp.route("/builder/library/fortinet/<product>/<version>/catalog", methods=["GET"])
@token_required("read")
def builder_library_catalog(product, version):
    """One build of the API library as an API Catalog version, exactly as an
    app package carries it in ``"apis"`` (contract §19). A connection pinned
    to ``api: <product>, api_version: <version>`` may call these endpoints
    and no other: the package check and the broker enforce it.

    Responses:
        200: ``{"api": {slug, name, owner, docs_url, description, version,
             base_path, operations, notes, source}}``.
        400: The version is malformed (``bad_request``).
        403: The product is not the token's ADOM (``wrong_product``).
        404: The build is not measured (``not_measured``).
        422: The product has no API Catalog form (``no_paths``). FortiAnalyzer
             has one since 2026-10-26: ``POST /jsonrpc`` with its urls in ``rpc``.
    """
    import re
    from ..services import builder_library as BL
    from ..services import studio_api_library as LIB
    refused = _adom_refusal()
    if refused:
        return refused
    if product not in BL.products_for(_product(), _owner()):
        return _err(403, "wrong_product", "The token's ADOM does not cover %s." % product[:40])
    if not re.match(r"^[0-9A-Za-z._-]{1,32}$", version):
        return _err(400, "bad_request", "Malformed version.")
    with _as_owner():
        try:
            res = {"api": LIB.entry(product, version)}
        except LIB.LibraryApiError as exc:
            code = "no_paths" if product not in LIB.STYLES else "not_measured"
            return _err(422 if code == "no_paths" else 404, code, str(exc))
        _audit("builder.library.catalog", target="%s %s" % (product, version),
               endpoints=len(res["api"]["operations"]))
    return jsonify(res)


@bp.route("/builder/data", methods=["GET"])
@limiter.limit("30/minute")
@token_required("read")
def builder_data():
    """This server's rows for the Builder's test data (contract §15).

    Query: ``datasets`` and ``stores`` (comma lists; absent = all, empty =
    none) and ``limit`` (rows per table, 1 to 2000, default 200). Datasets
    are what a view's render here would read for the token's owner (scoped
    and masked), data stores their declared columns plus ``_id``, and
    ``sources`` the ``satom_select`` lists. The owner must be a Plugin
    Studio author (``studio.script_library``), who reads the stores here.

    Responses:
        200: ``satom.builder-data/1``.
        403: The owner is not a Plugin Studio author (``owner_forbidden``), or the ADOM (``wrong_product``).
    """
    from ..services import builder_data as BD
    from ..services import studio_apps as SA
    refused = _adom_refusal()
    if refused:
        return refused
    if not SA.is_author(_owner()):
        return _err(403, "owner_forbidden", "The token's owner is not a Plugin Studio "
                    "author (studio.script_library).")
    with _as_owner():
        res = BD.sample(request.args.get("datasets"), request.args.get("stores"),
                        request.args.get("limit", BD.DEFAULT_LIMIT))
        _audit("builder.data", target=_product(), limit=res["limit"], **BD.counts(res))
    return jsonify(res)


@bp.route("/builder/validate", methods=["POST"])
@limiter.limit("30/minute")
@token_required("write")
def builder_validate():
    """Check a package against this server with the builder rules; writes nothing.

    Multipart ``package``. The answer is ``check()``'s result, HTTP 200 even
    when ``ok`` is false.

    Responses:
        200: ``{"ok", "problems", "warnings", "summary"}``.
        400: No ``package`` field, or ``options`` is not a JSON object (``bad_request``).
        403: The owner may not work in the token's ADOM (``wrong_product``).
        413: The package is larger than 10 MB (``too_large``).
    """
    from ..services import builder_target as BT
    from ..services import package_check
    refused = _adom_refusal()
    if refused:
        return refused
    data, _options, error = _package()
    if error:
        return error
    with _as_owner():
        res = package_check.check(data, BT.snapshot(_owner(), _product(),
                                                    scopes=g.api_token.scope_list), "builder")
        summary = res.get("summary") or {}
        _audit("builder.validate", target=str(summary.get("slug") or ""),
               ok=bool(res.get("ok")), problems=len(res.get("problems") or []))
    return jsonify(res)


@bp.route("/builder/rehearse", methods=["POST"])
@limiter.limit("30/minute")
@token_required("write")
def builder_rehearse():
    """Rehearse a package here, unarmed: nothing is installed or written.

    Multipart ``package`` plus ``options`` ``{"inputs": {}, "answers":
    "yes"|"no"|"stop"}``. An app's diagram is walked unarmed against this
    server's stores, connections and secrets (write and script steps are
    recorded, not executed); a view or widget is rendered in the sandbox. The
    owner must be a Plugin Studio author (``studio.script_library``).

    Responses:
        200: ``{"ok", "status", "steps", "outputs", "waiting", "error", "problems"}`` (a view: ``rendered``).
        400: No ``package`` field, or bad ``options`` (``bad_request``).
        403: The owner is not a Plugin Studio author (``owner_forbidden``), or the ADOM (``wrong_product``).
        409: Too many rehearsals at once (``busy``).
        413: The package is larger than 10 MB (``too_large``).
    """
    from ..services import builder_rehearse as BR
    from ..services import studio_apps as SA
    refused = _adom_refusal()
    if refused:
        return refused
    if not SA.is_author(_owner()):
        return _err(403, "owner_forbidden", "The token's owner is not a Plugin Studio "
                    "author (studio.script_library).")
    data, options, error = _package()
    if error:
        return error
    inputs = options.get("inputs") or {}
    if not isinstance(inputs, dict):
        return _err(400, "bad_request", "'inputs' must be an object.")
    answers = options.get("answers") or "yes"
    if answers not in BR.ANSWERS:
        return _err(400, "bad_request", "'answers' is yes, no or stop.")
    with _as_owner():
        try:
            res = BR.rehearse(data, user=_owner(), product=_product(), inputs=inputs,
                              answers=answers)
        except BR.Busy as exc:
            return _err(409, "busy", str(exc))
        _audit("builder.rehearse", ok=bool(res.get("ok")), status=res.get("status"),
               problems=len(res.get("problems") or []))
    return jsonify(res)


@bp.route("/builder/import", methods=["POST"])
@limiter.limit("30/minute")
@token_required("admin")
def builder_import():
    """Import a package: the same checks and install as the console's import.

    Multipart ``package`` plus ``options`` ``{"allow_downgrade": bool,
    "secrets": {"<connection slug>": "<secret>"}}``. Policy: ``import`` for a
    Vision EBC signature, ``builder`` for a publisher's signature or an
    unsigned package. ``secrets`` are stored for the connections the import
    CREATES (vault or encrypted setting), never logged; values for existing
    connections are ignored and reported in ``kept``. The owner must be a
    super-admin (``studio.plugin_studio``).

    Responses:
        200: ``{"ok", "kind", "slug", "version", "lands_in", "created", "kept", "todo", "problems"}``.
        400: No ``package`` field, or bad ``options`` (``bad_request``).
        403: The owner is not a super-admin (``owner_forbidden``), or the ADOM (``wrong_product``).
        413: The package is larger than 10 MB (``too_large``).
        422: The package was refused (``package_refused``); ``problems`` says why.
    """
    from ..services import plugin_import as PI
    refused = _adom_refusal()
    if refused:
        return refused
    if not _owner().can(SUPER_ADMIN):
        return _err(403, "owner_forbidden", "Importing needs a super-admin owner "
                    "(studio.plugin_studio).")
    data, options, error = _package()
    if error:
        return error
    secrets = options.get("secrets") or {}
    if not isinstance(secrets, dict):
        return _err(400, "bad_request", "'secrets' must be an object of slug: secret.")
    with _as_owner():
        try:
            rep = PI.import_package(data, user=_owner(), product=_product(), via="api",
                                    allow_downgrade=bool(options.get("allow_downgrade")),
                                    secrets=secrets, audit=audit_extra())
        except PI.ImportRefused as exc:
            _audit("builder.import.refused", problems=[p["message"] for p in exc.problems][:10])
            return _err(422, "package_refused", str(exc), problems=exc.problems)
    keep = ("ok", "kind", "slug", "version", "lands_in", "created", "kept", "todo",
            "problems", "warnings", "signed_by", "signer", "policy")
    return jsonify({k: rep.get(k) for k in keep})


@bp.route("/builder/publishers", methods=["GET"])
@token_required("read")
def builder_publishers():
    """The registered plugin publishers: key id, label, enabled, created.

    Responses:
        200: ``[{"key_id", "label", "enabled", "created_at"}]`` (contract §1).
    """
    from ..services import plugin_publishers as PP
    rows = [PP.as_json(r) for r in PP.list_publishers()]
    _audit("builder.publishers", target=_product(), count=len(rows))
    return jsonify(rows)


@bp.route("/builder/publishers", methods=["POST"])
@limiter.limit("30/minute")
@token_required("admin")
def builder_publishers_add():
    """Register a publisher key: ``{"label": str, "public_key": base64}``.

    ``public_key`` is the base64 of the raw 32-byte Ed25519 key; ``label`` at
    most 80 characters. Idempotent: the same key answers 200 with its
    existing ``key_id``. The owner must be a super-admin.

    Responses:
        201: ``{"key_id", "created": true}``.
        200: The key was already registered: ``{"key_id", "created": false}``.
        400: Bad JSON, label or key (``bad_request`` / ``invalid_key``).
        403: The owner is not a super-admin (``owner_forbidden``).
    """
    from ..services import plugin_publishers as PP
    if not _owner().can(SUPER_ADMIN):
        return _err(403, "owner_forbidden", "Registering a publisher needs a super-admin "
                    "owner (studio.plugin_studio).")
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return _err(400, "bad_request", "The body must be a JSON object.")
    label, key = body.get("label"), body.get("public_key")
    if not isinstance(label, str) or not isinstance(key, str):
        return _err(400, "bad_request", "'label' and 'public_key' are strings.")
    with _as_owner():
        try:
            row, created = PP.add(label, key, _owner().username)
        except PP.PublisherError as exc:
            return _err(400, "invalid_key", str(exc))
        if created:
            _audit("plugin.publisher.add", target=row.key_id, label=row.label)
    return jsonify({"key_id": row.key_id, "created": created}), (201 if created else 200)
