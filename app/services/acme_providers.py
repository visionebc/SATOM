"""ACME DNS-01 provider catalog + command/environment builder.

WHY THIS MODULE EXISTS
----------------------
An ACME client authenticates to a DNS provider through **environment
variables** — one set per provider, ~150 providers upstream. Hardcoding that
list in the app would mean a release every time a provider is added or an
upstream env var is renamed. So the catalog is a TABLE (:class:`AcmeDnsProvider`)
seeded INSERT-ONLY from the git-tracked ``acme_providers.yaml``, exactly like
the endpoint registry: operator edits win, a new provider is a row.

Three jobs live here:

1. :func:`seed_from_yaml` — boot seed (never overwrites an existing row).
2. :func:`env_for` — the provider's credentials, decrypted, as a ``dict`` of
   env vars **plus** the list of secret values so the caller can redact them
   from every log line. Credentials are never passed on the command line.
3. :func:`build_commands` — generates the submit/revoke command templates for
   the configured client from the catalog + the ACME settings, so the operator
   normally never writes a command by hand. A raw template is still allowed
   (``template_mode = "custom"``) for the cases nobody anticipated.

The generated templates use the SAME ``{token}`` contract as the ADCS path, so
:mod:`app.services.cert_manager` runs both through one code path.
"""
from __future__ import annotations

import json
import logging
import os

from ..models import AcmeDnsProvider, db
from . import settings_store as store

logger = logging.getLogger(__name__)

_YAML_NAME = "acme_providers.yaml"

# Well-known ACME directories (offered in the UI; the field stays free-text).
LE_PROD = "https://acme-v02.api.letsencrypt.org/directory"
LE_STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory"
KNOWN_DIRECTORIES = (
    ("Let's Encrypt — production", LE_PROD),
    ("Let's Encrypt — staging (test first!)", LE_STAGING),
    ("Buypass Go", "https://api.buypass.com/acme/directory"),
    ("Buypass Go — staging", "https://api.test4.buypass.no/acme/directory"),
    ("ZeroSSL (needs EAB)", "https://acme.zerossl.com/v2/DV90"),
    ("Google Trust Services (needs EAB)",
     "https://dv.acme-v02.api.pki.goog/directory"),
)


# --------------------------------------------------------------------------- #
#  Catalog                                                                      #
# --------------------------------------------------------------------------- #
def _yaml_path() -> str:
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    return os.path.join(root, _YAML_NAME)


def seed_from_yaml() -> int:
    """INSERT-ONLY seed. Returns the number of providers added."""
    path = _yaml_path()
    if not os.path.exists(path):
        return 0
    import yaml
    with open(path, "r", encoding="utf-8") as fh:
        doc = yaml.safe_load(fh) or {}
    rows = doc.get("providers") or []
    have = {p.slug for p in AcmeDnsProvider.query.all()}
    added = 0
    for i, row in enumerate(rows):
        slug = str((row or {}).get("slug") or "").strip()
        if not slug or slug in have:
            continue
        db.session.add(AcmeDnsProvider(
            slug=slug,
            label=str(row.get("label") or slug),
            flag=str(row.get("flag") or slug),
            doc_url=str(row.get("doc") or row.get("doc_url") or ""),
            fields=json.dumps(row.get("fields") or [], ensure_ascii=False),
            builtin=True, enabled=True, sort=(i + 1) * 10))
        added += 1
    if added:
        db.session.commit()
    return added


def catalog(*, enabled_only: bool = True) -> list[AcmeDnsProvider]:
    q = AcmeDnsProvider.query
    if enabled_only:
        q = q.filter(AcmeDnsProvider.enabled.is_(True))
    return q.order_by(AcmeDnsProvider.sort, AcmeDnsProvider.label).all()


def get(slug: str) -> AcmeDnsProvider | None:
    slug = (slug or "").strip()
    if not slug:
        return None
    return AcmeDnsProvider.query.filter_by(slug=slug).first()


def upsert(slug: str, values: dict) -> AcmeDnsProvider:
    """Create or edit a provider row (admin console)."""
    slug = (slug or "").strip().lower()
    if not slug:
        raise ValueError("slug is required")
    p = get(slug) or AcmeDnsProvider(slug=slug, builtin=False)
    p.label = str(values.get("label") or slug)
    p.flag = str(values.get("flag") or slug)
    p.doc_url = str(values.get("doc_url") or "")
    if "fields" in values:
        fields = values["fields"]
        if isinstance(fields, str):
            fields = json.loads(fields or "[]")
        clean = []
        for f in fields or []:
            env = str((f or {}).get("env") or "").strip()
            if not env:
                continue
            clean.append({"env": env,
                          "label": str(f.get("label") or env),
                          "secret": bool(f.get("secret")),
                          "required": bool(f.get("required")),
                          "help": str(f.get("help") or ""),
                          "default": str(f.get("default") or "")})
        p.fields = json.dumps(clean, ensure_ascii=False)
    if "enabled" in values:
        p.enabled = bool(values["enabled"])
    if values.get("sort") is not None:
        try:
            p.sort = int(values["sort"])
        except (TypeError, ValueError):
            pass
    db.session.add(p)
    db.session.commit()
    return p


def delete(slug: str) -> bool:
    """Delete a provider. Built-ins are never deleted (disable them instead) —
    otherwise the next boot would silently re-seed them."""
    p = get(slug)
    if not p or p.builtin:
        return False
    db.session.delete(p)
    db.session.commit()
    return True


# --------------------------------------------------------------------------- #
#  Credentials → process environment                                            #
# --------------------------------------------------------------------------- #
def env_for(slug: str) -> tuple[dict[str, str], list[str]]:
    """``({ENV: value}, [secret values])`` for a provider.

    The secret list is what the caller redacts from stdout/stderr/log — see
    ``cert_manager._redact_all``. Never log the dict itself."""
    p = get(slug)
    if not p:
        return {}, []
    stored = store.acme_provider_creds(slug, p.field_list, reveal=True)
    env, secrets = {}, []
    for f in p.field_list:
        name = f["env"]
        val = str(stored.get(name) or f.get("default") or "").strip()
        if not val:
            continue
        env[name] = val
        if f.get("secret"):
            secrets.append(val)
    return env, secrets


def missing_required(slug: str) -> list[str]:
    """Required env vars with no stored value — surfaced in the UI before the
    operator discovers it as a failed issuance."""
    p = get(slug)
    if not p:
        return []
    stored = store.acme_provider_creds(slug, p.field_list, reveal=True)
    out = []
    for f in p.field_list:
        if not f.get("required"):
            continue
        if not str(stored.get(f["env"]) or f.get("default") or "").strip():
            out.append(f["env"])
    return out


# --------------------------------------------------------------------------- #
#  Command generation                                                           #
# --------------------------------------------------------------------------- #
# Only tokens are emitted — the concrete values live in the mapping built by
# cert_manager._signing_context, so a value with spaces stays one argv element.
def build_commands(cfg: dict) -> tuple[str, str]:
    """(submit_cmd, revoke_cmd) generated for the configured client + challenge.

    ``cfg`` is :func:`settings_store.cert_manager_acme` output. Currently the
    generator targets **lego** (single static binary, ~150 DNS providers, all
    configured by environment). Any other client stays reachable through
    ``template_mode = "custom"``."""
    client = (cfg.get("client") or "lego").strip()
    if client != "lego":
        # No generator for this client — the operator supplies the templates.
        return (cfg.get("submit_cmd") or "").strip(), (cfg.get("revoke_cmd") or "").strip()

    # Flag names VERIFIED against lego 5.2.2 (`lego run --help`,
    # `lego certificates revoke --help`). In v5 every flag lives on the
    # SUBCOMMAND, EAB is `--eab.kid/--eab.hmac`, the propagation flags are
    # `--dns.propagation.wait` / `--dns.propagation.disable-ans`, and the
    # listeners are `--http.address` / `--tls.address` (not `.port`).
    common = []
    if cfg.get("account_email"):
        common += ["--email", "{email}"]
    if cfg.get("directory_url"):
        common += ["--server", "{directory}"]
    common += ["--path", "{acme_path}"]
    if cfg.get("eab_kid"):
        common += ["--eab", "--eab.kid", "{eab_kid}", "--eab.hmac", "{eab_hmac}"]

    submit = (["{helper}", "{out}", "{bin}", "run", "--accept-tos"] + common
              + ["--key-type", "{key_type}"])

    challenge = cfg.get("challenge") or "http-01"
    if challenge == "dns-01":
        submit += ["--dns", "{dns_flag}"]
        if cfg.get("dns_resolvers"):
            submit += ["--dns.resolvers", "{dns_resolvers}"]
        if cfg.get("dns_propagation_wait"):
            submit += ["--dns.propagation.wait", "{dns_propagation_wait}s"]
        if cfg.get("dns_disable_precheck"):
            submit += ["--dns.propagation.disable-ans"]
    elif challenge == "tls-alpn-01":
        submit += ["--tls", "--tls.address", ":{http_port}"]
    else:  # http-01
        submit += ["--http"]
        if (cfg.get("http_mode") or "webroot") == "webroot":
            submit += ["--http.webroot", "{webroot}"]
        else:
            submit += ["--http.address", ":{http_port}"]

    submit += ["--csr", "{csr}"]

    # Revocation keys on the certificate NAME in lego's store (the CN), and
    # reason 4 = superseded — which is what the lifecycle sweep is doing.
    revoke = (["{bin}", "certificates", "revoke"] + common
              + ["--cert.name", "{cn}", "--reason", "4"])
    return " ".join(submit), " ".join(revoke)
