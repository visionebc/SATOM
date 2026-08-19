"""Server Objects — the FortiWeb GUI **Server Objects** menu, web port.

Device → the GUI-faithful Server Objects menu (Server / Protected Hostnames /
Service / Certificates / SSL Ciphers / Global / X-Forwarded-For / IP Group) →
the live object list of a chosen type → the SAME generic recursive editor
(:mod:`app.views.objedit`) every other config area uses, so each object's
by-parent sub-tables (pool members, VIP list, SNI members, health rules, content
-routing match conditions…) are edited in place, several levels deep.

The menu SET + grouping comes from :mod:`app.services.server_objects` (explicit,
registry-resolved); the live OBJECTS are fetched here through
:class:`FortiWebClient` (parent-scoped reads via the editor). Reads are open to
any signed-in user; New/Edit/Delete are ``config_write`` + audited + dry-run
default, exactly like ``objedit``.
"""
from __future__ import annotations

from flask import Blueprint, render_template, request, abort
from flask_login import login_required

from ..auth.decorators import require_permission

from ..models import Appliance
from ..models import visible_appliances, visible_appliance_or_404
from ..clients.fortiweb import FortiWebClient
from ..services import objform
from ..services import cert_import
from ..services import server_objects as so

bp = Blueprint('server_objects', __name__, url_prefix='/server-objects')


def _row_view(obj: dict) -> dict:
    """A compact list-row projection (name + a couple of GUI-meaningful fields)."""
    if not isinstance(obj, dict):
        return {'name': str(obj), 'status': '', 'detail': ''}
    name = obj.get('name') or obj.get('mkey') or obj.get('id') or '—'
    status = obj.get('status') or ''
    # Pick the first non-empty "describing" field for a generic 2nd column.
    detail = ''
    for k in ('comment', 'comments', 'type', 'ip', 'ipv4-address', 'vip',
              'deployment-mode', 'server-balance', 'lb-algo', 'domain', 'port',
              'load-balance', 'persistence'):
        v = obj.get(k)
        if v not in (None, '', []):
            detail = '%s: %s' % (k, v)
            break
    return {'name': name, 'status': status, 'detail': detail}


@bp.route('/')
@login_required
def index():
    """Appliance picker — choose a device to browse its Server Objects."""
    appliances = visible_appliances().order_by(Appliance.name).all()
    from flask import redirect as _redir, url_for as _ufor
    from ..services import device_context as _dc
    _cur = _dc.current_appliance()
    if _cur is None:
        return _redir(_ufor('architecture.index'))
    return _redir(_ufor('server_objects.overview', id=_cur.id))


@bp.route('/<int:id>')
@login_required
def overview(id):
    """The Server Objects menu for one device, plus the selected type's objects.

    ``?type=<logical>`` selects a menu leaf; its live objects are fetched and
    listed. With no ``type`` the page shows the menu with a hint to pick one.
    """
    appliance = visible_appliance_or_404(id)
    menu = so.server_objects_menu()

    page = None
    selected = None
    rows: list[dict] = []
    error = None
    freshness = None
    logical = (request.args.get('type') or '').strip()
    if logical:
        # ``?type=`` names a TAB (one REST collection); its PAGE is what the
        # sidebar/breadcrumb show and what the tab strip is drawn from. Looking
        # the page up alone would render the DEFAULT tab's objects under the
        # requested tab's name.
        hit = so.find(logical)
        if hit is None:
            abort(404)
        page, selected = hit
        # DB-first: serve the object list from the local source of truth; the
        # device is touched only on an explicit refresh (server_objects.refresh).
        from ..services import read_layer
        payloads, meta = read_layer.read_objects(appliance.id, logical)
        rows = [_row_view(o) for o in payloads]
        freshness = read_layer.freshness_label(meta)

    return render_template(
        'server_objects/overview.html',
        appliance=appliance,
        menu=menu,
        page=page,
        selected=selected,
        rows=rows,
        error=error,
        freshness=freshness if logical else None,
        # A page whose REST create can NEVER succeed must not offer one: six
        # certificate collections answer -7721 to a cmdb POST even with a valid
        # PEM (see app.services.cert_import). They get Import (SSH) instead, and
        # a Local Certificate additionally gets Generate (Certificate Manager).
        import_spec=cert_import.spec_for(selected.collection) if selected else None,
        can_generate=cert_import.can_generate(selected.collection) if selected else False,
    )


def _pem_blocks(text: str, want: str) -> list[str]:
    """The ``-----BEGIN <want>...-----END <want>-----`` blocks inside ``text``.

    A pasted "certificate" is very often a fullchain. Only the FIRST block is the
    leaf; FortiWeb wants the leaf in ``certificate`` and the issuers in the
    Intermediate CA table, so the form has to be able to SEE how many there are.
    """
    import re as _re
    pat = _re.compile(
        r"-----BEGIN [A-Z0-9 ]*%s-----.*?-----END [A-Z0-9 ]*%s-----" % (want, want),
        _re.DOTALL)
    return [m.group(0) for m in pat.finditer(text or "")]


def _validate_pair(cert_pem: str, key_pem: str, passphrase: str) -> dict:
    """Parse the material and prove the key belongs to the certificate.

    Returns a summary dict, or raises ``ValueError`` with the operator-facing
    reason. Doing this BEFORE the SSH session is the point: FortiWeb accepts a
    mismatched pair and only fails later, at handshake time, on a policy that
    used to work.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
    except Exception as exc:  # noqa: BLE001
        raise ValueError(f"certificate is not a readable PEM: {exc}") from exc

    out = {
        'subject': cert.subject.rfc4514_string(),
        'issuer': cert.issuer.rfc4514_string(),
        'not_after': cert.not_valid_after_utc.isoformat(),
        'serial': format(cert.serial_number, 'x'),
        'key_matches': None,
    }
    if not key_pem:
        return out
    try:
        key = serialization.load_pem_private_key(
            key_pem.encode(), password=(passphrase.encode() if passphrase else None))
    except TypeError as exc:  # key is encrypted and no passphrase given
        raise ValueError("the private key is encrypted — enter its passphrase") from exc
    except ValueError as exc:
        raise ValueError(f"private key is not readable: {exc}") from exc
    pub_a = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    pub_b = cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    if pub_a != pub_b:
        raise ValueError("this private key does NOT belong to this certificate "
                         "(public keys differ) — refusing to upload the pair")
    out['key_matches'] = True
    return out


@bp.route('/<int:id>/import', methods=['GET', 'POST'])
@login_required
@require_permission('config_write')
def import_object(id):
    """Import certificate material into one of the six SSH-only collections.

    REST cmdb cannot create these at all (``-7721`` even with a valid PEM), so
    this is the ONLY path that works — and it goes through the certificate-only
    SSH door (:mod:`app.services.cert_ssh`), which can emit nothing but a
    ``config system certificate <table>`` block.
    """
    from flask import redirect, url_for, flash
    from flask_login import current_user
    from ..services import cert_ssh

    appliance = visible_appliance_or_404(id)
    logical = (request.args.get('type') or request.form.get('type') or '').strip()
    hit = so.find(logical)
    if hit is None:
        abort(404)
    page, selected = hit
    spec = cert_import.spec_for(selected.collection)
    if spec is None:
        # REST CAN create this one — sending it here would teach operators a
        # second, privileged path for objects that never needed it.
        abort(404)

    form = {'name': '', 'cert_pem': '', 'key_pem': ''}
    summary = None
    error = None
    if request.method == 'POST':
        form['name'] = (request.form.get('name') or '').strip()
        form['cert_pem'] = (request.form.get('cert_pem') or '').strip()
        form['key_pem'] = (request.form.get('key_pem') or '').strip()
        passphrase = request.form.get('passphrase') or ''
        try:
            cert_ssh.assert_cert_name(form['name'])
            leaves = _pem_blocks(form['cert_pem'], 'CERTIFICATE')
            if not leaves:
                raise ValueError("no PEM certificate found in the certificate box")
            if spec.key_field and not form['key_pem']:
                raise ValueError(f"{spec.label} needs its {spec.key_label.lower()}")
            summary = _validate_pair(form['cert_pem'], form['key_pem'], passphrase)
            summary['blocks'] = len(leaves)
            cert_ssh.import_into(appliance, selected.collection, form['name'],
                                 form['cert_pem'], form['key_pem'], passphrase,
                                 secret=appliance.password)
            # The destination has to LIST IT BACK. A CLI block with an empty
            # value does not raise — it creates an entry with no material and
            # reports success, which is the failure this re-read exists to catch.
            client = appliance.build_client()
            rows = client._safe_list(objform.rest_path(selected.collection)) or []
            names = {str(r.get('name')) for r in rows if isinstance(r, dict)}
            if form['name'] not in names:
                raise ValueError(
                    f"{appliance.name} does not list {form['name']} back after the "
                    "import — treat it as NOT imported")
            from ..services import audit
            audit.log_action('server_objects.import',
                             target=f"{appliance.name}:{selected.collection}:{form['name']}",
                             extra={'collection': selected.collection,
                                    'appliance_id': appliance.id,
                                    'transport': 'ssh',
                                    'has_key': bool(spec.key_field)})
            flash(f"Imported {form['name']} into {spec.label} on {appliance.name}.",
                  "success")
            return redirect(url_for('server_objects.overview', id=id, type=logical))
        except Exception as exc:  # noqa: BLE001 — every failure is operator-facing
            error = str(exc)

    return render_template(
        'server_objects/import.html',
        appliance=appliance, menu=so.server_objects_menu(),
        page=page, selected=selected, spec=spec,
        form=form, summary=summary, error=error,
    )


@bp.route('/<int:id>/refresh', methods=['POST'])
@login_required
def refresh(id):
    """Pull live config into the local source of truth, then return to the
    selected Server Objects type (DB-first)."""
    from flask import redirect, url_for, flash
    from flask_login import current_user
    appliance = visible_appliance_or_404(id)
    logical = (request.form.get('type') or '').strip()
    try:
        from ..services import device_sync
        run = device_sync.sync_device(appliance, publish=False,
                                      user_label=getattr(current_user, 'username', None),
                                      trigger='manual')
        flash(f"Refreshed from {appliance.name}: {run.detail}",
              "success" if run.status == 'ok' else "danger")
    except Exception as exc:  # noqa: BLE001
        flash(f"Refresh failed: {exc}", "danger")
    return redirect(url_for('server_objects.overview', id=id, type=logical) if logical
                    else url_for('server_objects.overview', id=id))
