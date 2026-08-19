"""Where a credential actually LIVES — local Fernet or an external vault.

SATOM has always kept appliance passwords, directory bind passwords and the
FortiAuthenticator shared secret Fernet-encrypted in its own database. That is
still the default and it still works on its own: this module adds a SECOND
place a secret can live, it does not replace the first one.

Why a second place at all
-------------------------
Fernet encrypts at rest, but ``FERNET_KEY`` lives in ``/opt/satom/.env`` on the
SAME host as the database it decrypts. Whoever can read that disk can read every
appliance password. An external vault moves the key material off the node, so a
stolen database (or a stray ``.env.bak``) decrypts nothing.

The three modes, and what each one actually costs
-------------------------------------------------
``local``   — Fernet only. The vault is never contacted. **Default**, and the
              behaviour of every install that never opens this page.
``mirror``  — writes go to BOTH; reads try the vault first and fall back to the
              local copy. Nothing breaks if the vault is down, and nothing is
              lost if it is wiped. This is the migration mode — but note that
              the local copy still exists, so the ``.env`` exposure is NOT yet
              closed. Mirror is a stepping stone, not a destination.
``vault``   — the vault is the only copy; the local column holds a sentinel.
              This is the mode that actually closes the exposure, and the mode
              in which a vault outage makes credentials unavailable. A read
              failure RAISES: returning "" would hand an empty password to a
              login attempt and lock the account out on the appliance.

Read-through, never read-and-cache
----------------------------------
Only the auth token is cached (one login per TTL, not one per secret — a fleet
sweep over 100 appliances would otherwise open 100 sessions). The secret values
themselves are always fetched, so the vault's audit log stays truthful about who
read what and when. That audit trail is half the reason to run a vault.
"""
from __future__ import annotations

import json
import logging
import ssl
import threading
import time
import urllib.error
import urllib.request

from ..models import AppSetting
from . import encryption

log = logging.getLogger(__name__)

K_CONFIG = "vault.config"

MODE_LOCAL = "local"
MODE_MIRROR = "mirror"
MODE_VAULT = "vault"
MODES = (MODE_LOCAL, MODE_MIRROR, MODE_VAULT)

MODE_LABELS = {
    MODE_LOCAL: "Store in SATOM only (Fernet)",
    MODE_MIRROR: "Store in both — read vault first, fall back to SATOM",
    MODE_VAULT: "Store in the vault only",
}

# Written into ``password_enc`` when the vault owns the secret. It is a valid
# Fernet token of this literal, so an old code path that decrypts blindly gets
# a readable marker instead of a crash or — far worse — a silent "".
VAULT_SENTINEL = "__stored-in-vault__"

DEFAULTS = {
    "enabled": False,
    "mode": MODE_LOCAL,
    "addr": "",
    "mount": "satom",
    "auth": "approle",          # approle | token
    "role_id": "",
    "secret_id_enc": "",
    "token_enc": "",
    "ca_cert": "",              # PEM, pasted or path
    "verify_tls": True,
    "timeout": 10,
    "namespace": "",
}

# Fields the UI must never echo back.
SECRET_FIELDS = ("secret_id", "token")

_token_lock = threading.Lock()
_token_cache: dict = {"token": "", "expires": 0.0, "fingerprint": ""}


class VaultError(RuntimeError):
    """The vault was asked for something and could not answer."""


# ---------------------------------------------------------------------------
# configuration
# ---------------------------------------------------------------------------
def _raw() -> dict:
    try:
        val = AppSetting.get(K_CONFIG)
    except Exception:  # no app context / table not migrated yet
        return {}
    if not val:
        return {}
    try:
        out = json.loads(val)
    except (TypeError, ValueError):
        return {}
    return out if isinstance(out, dict) else {}


def config(reveal: bool = False) -> dict:
    """Public view of the configuration. Secrets are blanked unless *reveal*."""
    cfg = dict(DEFAULTS)
    cfg.update({k: v for k, v in _raw().items() if k in DEFAULTS})
    cfg["enabled"] = bool(cfg.get("enabled"))
    cfg["verify_tls"] = bool(cfg.get("verify_tls"))
    if cfg.get("mode") not in MODES:
        cfg["mode"] = MODE_LOCAL
    try:
        cfg["timeout"] = max(1, min(120, int(cfg.get("timeout") or 10)))
    except (TypeError, ValueError):
        cfg["timeout"] = 10

    # "has_" flags, never the value: the page has to show that a secret_id is
    # set without ever putting it in the HTML.
    cfg["has_secret_id"] = bool(cfg.get("secret_id_enc"))
    cfg["has_token"] = bool(cfg.get("token_enc"))
    cfg["secret_id"] = _dec(cfg.get("secret_id_enc", "")) if reveal else ""
    cfg["token"] = _dec(cfg.get("token_enc", "")) if reveal else ""
    cfg["configured"] = bool(cfg.get("addr")) and (
        bool(cfg.get("role_id")) and cfg["has_secret_id"] if cfg.get("auth") == "approle"
        else cfg["has_token"])
    return cfg


def _dec(token: str) -> str:
    if not token:
        return ""
    try:
        return encryption.decrypt(token)
    except Exception:
        log.warning("vault: stored credential could not be decrypted")
        return ""


def save(form: dict) -> dict:
    """Persist the configuration. Blank secret fields KEEP the stored value.

    That convention is copied from the git token and SFTP password fields
    on this same page — a page that re-renders with blank secret inputs would
    otherwise wipe the credential every time an unrelated checkbox is toggled.
    """
    cur = _raw()
    out = dict(DEFAULTS)
    out.update({k: v for k, v in cur.items() if k in DEFAULTS})

    mode = (form.get("mode") or MODE_LOCAL).strip()
    out["mode"] = mode if mode in MODES else MODE_LOCAL
    out["enabled"] = bool(form.get("enabled"))
    out["addr"] = (form.get("addr") or "").strip().rstrip("/")
    out["mount"] = (form.get("mount") or "satom").strip().strip("/") or "satom"
    out["auth"] = "token" if (form.get("auth") or "approle") == "token" else "approle"
    out["role_id"] = (form.get("role_id") or "").strip()
    out["ca_cert"] = (form.get("ca_cert") or "").strip()
    out["namespace"] = (form.get("namespace") or "").strip()
    out["verify_tls"] = bool(form.get("verify_tls"))
    try:
        out["timeout"] = max(1, min(120, int(form.get("timeout") or 10)))
    except (TypeError, ValueError):
        out["timeout"] = 10

    for field in SECRET_FIELDS:
        val = (form.get(field) or "").strip()
        if val:
            out[field + "_enc"] = encryption.encrypt(val)

    # Enabling without a reachable configuration is how an operator locks
    # themselves out of every appliance at once. Refuse it here, not later.
    if out["enabled"] and not out["addr"]:
        raise ValueError("A vault address is required before enabling the vault.")

    AppSetting.set(K_CONFIG, json.dumps(out))
    invalidate_token()
    return config()


def invalidate_token() -> None:
    with _token_lock:
        _token_cache.update({"token": "", "expires": 0.0, "fingerprint": ""})


def active() -> bool:
    """True when the vault is on the read/write path at all."""
    cfg = config()
    return bool(cfg["enabled"]) and cfg["mode"] in (MODE_MIRROR, MODE_VAULT) and cfg["configured"]


def authoritative() -> bool:
    """True when the vault is the ONLY copy (a failed read must not fall back)."""
    return active() and config()["mode"] == MODE_VAULT


# ---------------------------------------------------------------------------
# transport
# ---------------------------------------------------------------------------
def _ssl_context(cfg: dict):
    if not cfg.get("verify_tls"):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    ca = (cfg.get("ca_cert") or "").strip()
    if ca.startswith("-----BEGIN"):
        ctx = ssl.create_default_context()
        ctx.load_verify_locations(cadata=ca)
        return ctx
    if ca:
        return ssl.create_default_context(cafile=ca)
    return ssl.create_default_context()


def _request(cfg: dict, method: str, path: str, token: str = "", body=None) -> dict:
    url = "%s/v1/%s" % (cfg["addr"], path.lstrip("/"))
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("X-Vault-Token", token)
    if cfg.get("namespace"):
        req.add_header("X-Vault-Namespace", cfg["namespace"])
    try:
        with urllib.request.urlopen(req, context=_ssl_context(cfg),
                                    timeout=cfg["timeout"]) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = json.loads(exc.read() or b"{}").get("errors", [""])[0]
        except Exception:
            pass
        raise VaultError("%s %s -> HTTP %s%s" % (
            method, path, exc.code, (": " + detail) if detail else "")) from exc
    except Exception as exc:
        raise VaultError("%s %s -> %s" % (method, path, exc)) from exc
    return json.loads(raw) if raw else {}


def _fingerprint(cfg: dict) -> str:
    """Identity of the credential the cached token was minted from.

    Without this, changing the AppRole and pressing Save would keep serving the
    OLD token until its TTL ran out — the new configuration would look like it
    worked while the old one was still doing the work.
    """
    return "|".join([cfg["addr"], cfg["auth"], cfg["role_id"],
                     cfg.get("secret_id_enc", "")[:24], cfg.get("token_enc", "")[:24]])


def _token(cfg: dict) -> str:
    now = time.time()
    fp = _fingerprint(cfg)
    with _token_lock:
        if _token_cache["token"] and _token_cache["expires"] > now and _token_cache["fingerprint"] == fp:
            return _token_cache["token"]

    if cfg["auth"] == "token":
        tok = _dec(cfg.get("token_enc", ""))
        if not tok:
            raise VaultError("no vault token configured")
        # A static token has no lease we minted; re-read it every 5 minutes so a
        # rotated token is picked up without a restart.
        ttl = 300.0
    else:
        secret_id = _dec(cfg.get("secret_id_enc", ""))
        if not cfg["role_id"] or not secret_id:
            raise VaultError("AppRole is not fully configured (role_id + secret_id)")
        res = _request(cfg, "POST", "auth/approle/login",
                       body={"role_id": cfg["role_id"], "secret_id": secret_id})
        auth = res.get("auth") or {}
        tok = auth.get("client_token") or ""
        if not tok:
            raise VaultError("AppRole login returned no token")
        # Renew at 2/3 of the lease: waiting for expiry means the first request
        # after it is the one that fails.
        ttl = max(30.0, float(auth.get("lease_duration") or 3600) * 0.66)

    with _token_lock:
        _token_cache.update({"token": tok, "expires": time.time() + ttl, "fingerprint": fp})
    return tok


# ---------------------------------------------------------------------------
# KV v2
# ---------------------------------------------------------------------------
def read(path: str) -> dict | None:
    """Read a KV v2 secret. ``None`` means "not there", which is not an error."""
    cfg = config(reveal=False)
    tok = _token(cfg)
    try:
        res = _request(cfg, "GET", "%s/data/%s" % (cfg["mount"], path.strip("/")), token=tok)
    except VaultError as exc:
        if "HTTP 404" in str(exc):
            return None
        raise
    data = ((res.get("data") or {}).get("data"))
    return data if isinstance(data, dict) else None


def write(path: str, data: dict) -> None:
    cfg = config(reveal=False)
    tok = _token(cfg)
    _request(cfg, "POST", "%s/data/%s" % (cfg["mount"], path.strip("/")),
             token=tok, body={"data": {k: ("" if v is None else str(v)) for k, v in data.items()}})


def delete(path: str) -> None:
    """Soft-delete the latest version (metadata and old versions survive)."""
    cfg = config(reveal=False)
    tok = _token(cfg)
    try:
        _request(cfg, "DELETE", "%s/data/%s" % (cfg["mount"], path.strip("/")), token=tok)
    except VaultError as exc:
        if "HTTP 404" not in str(exc):
            raise


def health() -> dict:
    """What the Test connection button reports. Never raises."""
    cfg = config(reveal=False)
    out = {"ok": False, "sealed": None, "version": "", "detail": "", "policies": [],
           "mount_ok": False}
    if not cfg["addr"]:
        out["detail"] = "No vault address configured."
        return out
    try:
        res = _request(cfg, "GET", "sys/health")
        out["sealed"] = bool(res.get("sealed"))
        out["version"] = res.get("version") or ""
        if out["sealed"]:
            out["detail"] = "The vault is reachable but SEALED — it cannot answer for secrets."
            return out
    except VaultError as exc:
        out["detail"] = "Unreachable: %s" % exc
        return out

    try:
        tok = _token(cfg)
    except VaultError as exc:
        out["detail"] = "Reachable, but authentication failed: %s" % exc
        return out

    try:
        info = _request(cfg, "GET", "auth/token/lookup-self", token=tok)
        out["policies"] = (info.get("data") or {}).get("policies") or []
    except VaultError:
        pass

    # Reaching the mount is the check that matters: a token with the wrong
    # policy authenticates fine and then fails on every real read.
    try:
        _request(cfg, "GET", "%s/metadata?list=true" % cfg["mount"], token=tok)
        out["mount_ok"] = True
    except VaultError as exc:
        if "HTTP 404" in str(exc):
            out["mount_ok"] = True   # mount exists, simply empty
        else:
            out["detail"] = "Authenticated, but mount %r is not readable: %s" % (cfg["mount"], exc)
            return out

    out["ok"] = True
    out["detail"] = "Vault %s reachable, unsealed, mount %r readable." % (
        out["version"] or "?", cfg["mount"])
    return out


# ---------------------------------------------------------------------------
# the callers' view: appliances, directory secrets, git
# ---------------------------------------------------------------------------
def appliance_path(name: str) -> str:
    return "appliances/%s" % (name or "").strip()


def get_appliance_password(name: str) -> str | None:
    """The password for *name*, or ``None`` to mean "use the local copy".

    ``None`` is returned when the vault is simply not on the path. It is NOT
    returned when the vault is authoritative and the read fails — that raises,
    because falling back to a local sentinel would send the literal
    ``__stored-in-vault__`` to an appliance as a password.
    """
    if not active():
        return None
    try:
        data = read(appliance_path(name))
    except VaultError as exc:
        if authoritative():
            raise
        log.warning("vault: read failed for %s, falling back to local copy: %s", name, exc)
        return None
    if data and data.get("password"):
        return data["password"]
    if authoritative():
        raise VaultError(
            "appliance %r has no password in the vault, and the vault is the "
            "only configured store" % name)
    return None


def put_appliance_password(appliance, plaintext: str) -> bool:
    """Mirror *plaintext* into the vault. Returns True when it landed there."""
    if not active():
        return False
    # The path IS the name. A row whose name is not set yet (the password
    # setter can fire before the rest of the form is applied) would write to
    # ``appliances/`` — one shared path that every unnamed appliance overwrites.
    if not (appliance.name or "").strip():
        log.warning("vault: refusing to store a password for an unnamed appliance")
        return False
    write(appliance_path(appliance.name), {
        "username": appliance.username or "",
        "password": plaintext,
        "host": appliance.host or "",
        "port": appliance.port or "",
        "kind": appliance.kind or "",
        "vdom": appliance.vdom or "",
        "satom_appliance_id": appliance.id or "",
    })
    return True


def get_field(path: str, field: str) -> str | None:
    """Generic read for the non-appliance secrets (RADIUS, LDAP bind, git)."""
    if not active():
        return None
    try:
        data = read(path)
    except VaultError as exc:
        if authoritative():
            raise
        log.warning("vault: read failed for %s, falling back to local: %s", path, exc)
        return None
    if data and data.get(field):
        return data[field]
    return None


def put_field(path: str, field: str, value: str, extra: dict | None = None) -> bool:
    if not active():
        return False
    data = {}
    try:
        data = read(path) or {}
    except VaultError:
        data = {}
    data.update(extra or {})
    data[field] = value
    write(path, data)
    return True


# ---------------------------------------------------------------------------
# migration
# ---------------------------------------------------------------------------
def migrate_local_to_vault(dry_run: bool = True) -> dict:
    """Copy every locally-stored credential into the vault.

    Every copy is READ BACK and compared before it counts. A write that returns
    200 and stores nothing is the failure this exists to catch, and it is
    invisible to a caller that only checks the status code.

    The local copies are left alone. Removing them is a separate, deliberate
    step — this function must be safe to run twice, and safe to run before the
    operator has decided to trust the vault.
    """
    from ..models import Appliance

    out = {"dry_run": bool(dry_run), "copied": 0, "failed": 0, "skipped": 0,
           "items": [], "ok": True}

    def note(kind, name, status, detail=""):
        out["items"].append({"kind": kind, "name": name, "status": status,
                             "detail": detail})
        if status == "copied":
            out["copied"] += 1
        elif status == "skipped":
            out["skipped"] += 1
        else:
            out["failed"] += 1
            out["ok"] = False

    if not config()["configured"]:
        out["ok"] = False
        out["error"] = "The vault is not configured yet."
        return out

    for app in Appliance.query.order_by(Appliance.name).all():
        if not (app.name or "").strip():
            note("appliance", "(unnamed)", "skipped", "row has no name")
            continue
        try:
            local = encryption.decrypt(app.password_enc) if app.password_enc else ""
        except Exception as exc:  # noqa: BLE001
            note("appliance", app.name, "failed", "local copy undecryptable: %s" % exc)
            continue
        if not local:
            note("appliance", app.name, "skipped", "no local password stored")
            continue
        if local == VAULT_SENTINEL:
            note("appliance", app.name, "skipped", "already vault-owned")
            continue
        if dry_run:
            note("appliance", app.name, "copied", "would copy")
            continue
        try:
            write(appliance_path(app.name), {
                "username": app.username or "", "password": local,
                "host": app.host or "", "port": app.port or "",
                "kind": app.kind or "", "vdom": app.vdom or "",
                "satom_appliance_id": app.id or "",
            })
            back = read(appliance_path(app.name)) or {}
            if back.get("password") != local:
                note("appliance", app.name, "failed", "read-back did not match")
            else:
                note("appliance", app.name, "copied", "verified")
        except VaultError as exc:
            note("appliance", app.name, "failed", str(exc))

    # Directory secrets live in app_settings, not in a table we can iterate.
    for label, key, path, field in (
        ("FortiAuthenticator shared secret", "auth.radius.secret_enc",
         "auth/fortiauthenticator", "shared_secret"),
        ("LDAP/AD bind password", "auth.ldap.bind_password_enc",
         "auth/ldap", "bind_password"),
    ):
        raw = AppSetting.get(key)
        if not raw:
            note("setting", label, "skipped", "not configured")
            continue
        try:
            local = encryption.decrypt(raw)
        except Exception as exc:  # noqa: BLE001
            note("setting", label, "failed", "local copy undecryptable: %s" % exc)
            continue
        if local == VAULT_SENTINEL:
            note("setting", label, "skipped", "already vault-owned")
            continue
        if dry_run:
            note("setting", label, "copied", "would copy")
            continue
        try:
            put_field(path, field, local)
            back = read(path) or {}
            note("setting", label,
                 "copied" if back.get(field) == local else "failed",
                 "verified" if back.get(field) == local else "read-back did not match")
        except VaultError as exc:
            note("setting", label, "failed", str(exc))

    return out
