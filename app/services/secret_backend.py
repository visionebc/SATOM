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
import urllib.parse
import urllib.request

from flask import has_app_context

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


class VaultConfigUnavailable(RuntimeError):
    """This process cannot READ where the secret lives, so it must not guess.

    Deliberately NOT a ``VaultError``: ``get_appliance_password`` catches that
    one and falls back to the local copy, which is exactly the silent
    degradation this class exists to stop.
    """


# ---------------------------------------------------------------------------
# configuration
# ---------------------------------------------------------------------------
def _raw() -> dict:
    # "I cannot read the configuration" is NOT "the vault is switched off", and
    # until 2026-09-14 this `except` confused the two. A thread with no app
    # context (the badge pool in api/appliances.py) got {} -> active() False ->
    # get_appliance_password() None = "use the local copy" -> the local copy is
    # the sentinel -> the getter raises -> probe_status returns "offline". The
    # whole inventory marked offline, for 3.5 weeks, without a single log line.
    #
    # Breaking LOUDLY is the fix: the symptom reappears in the next code path
    # that uses threads, and there would be no log there either.
    if not has_app_context():
        raise VaultConfigUnavailable(
            "vault configuration was read with no Flask app context, so this "
            "process cannot tell whether a vault owns the secret; push an "
            "app_context() inside the worker instead of guessing")
    try:
        val = AppSetting.get(K_CONFIG)
    except Exception:  # table not migrated yet (fresh install, pre-Alembic)
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
    # urllib also opens file:// (and a '#' in the address cuts off the /v1/...
    # suffix), which would turn the vault-address setting into a way to read
    # this node's files. A vault is a network service; refuse anything else.
    if urllib.parse.urlsplit(url).scheme not in ("http", "https"):
        raise VaultError("the vault address must be an http(s) URL (got %r)"
                         % str(cfg.get("addr") or "")[:80])
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
    with _writing(path):
        cfg = config(reveal=False)
        tok = _token(cfg)
        _request(cfg, "POST", "%s/data/%s" % (cfg["mount"], path.strip("/")),
                 token=tok, body={"data": {k: ("" if v is None else str(v)) for k, v in data.items()}})


# ---------------------------------------------------------------------------
# stale vault copies (mirror mode)
# ---------------------------------------------------------------------------
#: In ``mirror`` a vault write that fails is not an error for the caller: the
#: local copy is written anyway, as the mode promises. But the vault still
#: holds the PREVIOUS value, and every read goes to the vault first — so a
#: password or HMAC secret rotated while the vault was down silently reverted
#: to the old one as soon as the vault came back (2026-10-19). A path whose
#: vault write failed gets one row here; reads skip the vault for it until a
#: write succeeds (an edit, or Settings > Vault > Migrate).
#:
#: Staged in the caller's session, NOT committed here: the marker must land in
#: the same transaction as the newer local copy it points at. Committing here
#: would also commit whatever half-applied form the caller has pending.
K_STALE_PREFIX = "vault.stale."


def _stale_key(path: str) -> str:
    # Hashed: the key column is 128 characters and appliance names are free.
    import hashlib
    return K_STALE_PREFIX + hashlib.sha256(
        path.strip("/").encode("utf-8")).hexdigest()[:32]


def _stage_stale(path: str, stale: bool) -> None:
    from ..extensions import db
    key = _stale_key(path)
    row = db.session.get(AppSetting, key)
    if stale:
        if row is None:
            row = AppSetting(key=key)
            db.session.add(row)
        row.value = json.dumps({"path": path.strip("/"),
                                "at": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                                    time.gmtime())})
    elif row is not None:
        db.session.delete(row)


def is_stale(path: str) -> bool:
    try:
        return AppSetting.get(_stale_key(path)) is not None
    except Exception:  # noqa: BLE001 — table not there yet: nothing is stale
        return False


def stale_paths() -> list:
    """Vault paths whose copy is older than SATOM's, oldest-first."""
    rows = AppSetting.query.filter(
        AppSetting.key.like(K_STALE_PREFIX + "%")).all()
    out = []
    for row in rows:
        try:
            out.append(json.loads(row.value))
        except (TypeError, ValueError):
            out.append({"path": "?", "at": ""})
    return sorted(out, key=lambda d: d.get("at", ""))


class _writing:
    """Mark *path* stale when the write fails outside vault-only mode, clear
    the mark when it succeeds. In vault-only mode a failed write is refused by
    every caller and the local copy is not touched, so the vault copy is still
    the newest one there is."""

    def __init__(self, path: str):
        self.path = path

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            if exc_type is None:
                _stage_stale(self.path, False)
            elif not authoritative():
                _stage_stale(self.path, True)
        except Exception:  # noqa: BLE001 — never mask the write's own outcome
            log.warning("vault: could not record the state of %s", self.path,
                        exc_info=True)
        return False


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
    # Reachable now is not the same as up to date: a write that failed while it
    # was not left the vault with the previous value of these secrets.
    try:
        stale = stale_paths()
    except Exception:  # noqa: BLE001
        stale = []
    out["stale"] = [d.get("path", "?") for d in stale]
    if stale:
        out["detail"] += (
            " %d secret(s) changed while the vault could not be written (%s): "
            "the vault copy is OLDER, so SATOM uses its own copy until you run "
            "“Migrate existing credentials”." % (
                len(stale), ", ".join(out["stale"][:10])))
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
    if is_stale(appliance_path(name)):
        return None   # SATOM's copy is the newer one; see K_STALE_PREFIX
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
    record = {
        "username": appliance.username or "",
        "password": plaintext,
        "host": appliance.host or "",
        "port": appliance.port or "",
        "kind": appliance.kind or "",
        "vdom": appliance.vdom or "",
        "satom_appliance_id": appliance.id or "",
    }
    # A KV v2 write REPLACES the record: rotating the API credential must not
    # silently drop the separate SSH login stored beside it. A failed read
    # raises rather than writing a record that would lose it.
    with _writing(appliance_path(appliance.name)):
        # ...and the same for the SNMP community (services/snmp_collect).
        kept_fields = [f for f, col in (("ssh_password", "ssh_password_enc"),
                                        ("snmp_community", "snmp_community_enc"))
                       if getattr(appliance, col, None)]
        if kept_fields:
            before = read(appliance_path(appliance.name)) or {}
            for f in kept_fields:
                if before.get(f):
                    record[f] = before[f]
        write(appliance_path(appliance.name), record)
    return True


def get_appliance_ssh_password(name: str) -> str | None:
    """The separate SSH login for *name*, or ``None`` = "use the local copy".
    Same failure contract as :func:`get_appliance_password`."""
    if not active():
        return None
    if is_stale(appliance_path(name)):
        return None   # SATOM's copy is the newer one; see K_STALE_PREFIX
    try:
        data = read(appliance_path(name))
    except VaultError as exc:
        if authoritative():
            raise
        log.warning("vault: read failed for %s, falling back to local copy: %s", name, exc)
        return None
    if data and data.get("ssh_password"):
        return data["ssh_password"]
    if authoritative():
        raise VaultError(
            "appliance %r has no SSH password in the vault, and the vault is "
            "the only configured store" % name)
    return None


def put_appliance_ssh_password(appliance, plaintext: str) -> bool:
    """Store (or, with ``""``, remove) the SSH login beside the API credential.
    Read-modify-write so the API ``password`` in the same record survives."""
    if not active():
        return False
    if not (appliance.name or "").strip():
        log.warning("vault: refusing to store an SSH password for an unnamed appliance")
        return False
    with _writing(appliance_path(appliance.name)):
        data = read(appliance_path(appliance.name)) or {}
        if plaintext:
            data["ssh_password"] = plaintext
        else:
            data.pop("ssh_password", None)
        write(appliance_path(appliance.name), data)
    return True


def get_field(path: str, field: str) -> str | None:
    """Generic read for the non-appliance secrets (RADIUS, LDAP bind, git)."""
    if not active():
        return None
    if is_stale(path):
        return None   # SATOM's copy is the newer one; see K_STALE_PREFIX
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
        ssh_local = ""
        if getattr(app, "ssh_password_enc", None):
            try:
                ssh_local = encryption.decrypt(app.ssh_password_enc)
            except Exception as exc:  # noqa: BLE001
                note("appliance", app.name, "failed",
                     "local SSH copy undecryptable: %s" % exc)
                continue
            if ssh_local == VAULT_SENTINEL:
                ssh_local = ""
        try:
            record = {
                "username": app.username or "", "password": local,
                "host": app.host or "", "port": app.port or "",
                "kind": app.kind or "", "vdom": app.vdom or "",
                "satom_appliance_id": app.id or "",
            }
            if ssh_local:
                record["ssh_password"] = ssh_local
            write(appliance_path(app.name), record)
            back = read(appliance_path(app.name)) or {}
            if ssh_local and back.get("ssh_password") != ssh_local:
                note("appliance", app.name, "failed", "SSH read-back did not match")
            elif back.get("password") != local:
                note("appliance", app.name, "failed", "read-back did not match")
            else:
                note("appliance", app.name, "copied", "verified")
        except VaultError as exc:
            note("appliance", app.name, "failed", str(exc))

    # Directory secrets live in app_settings, not in a table we can iterate.
    for label, key, path, field in SETTING_SECRETS:
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

    # Integration-hook and Python Studio connection secrets: one app_settings
    # row per name (_PREFIXED_SECRETS).
    for kind, prefix, path_of in _PREFIXED_SECRETS:
        for key, name, local in _prefixed_secret_rows(kind, prefix, note):
            if local == VAULT_SENTINEL:
                note(kind, name, "skipped", "already vault-owned")
                continue
            if dry_run:
                note(kind, name, "copied", "would copy")
                continue
            try:
                put_field(path_of(name), "value", local)
                back = (read(path_of(name)) or {}).get("value")
                note(kind, name, "copied" if back == local else "failed",
                     "verified" if back == local else "read-back did not match")
            except VaultError as exc:
                note(kind, name, "failed", str(exc))

    if not dry_run:
        # Every verified copy cleared its stale mark in write(); persist that.
        from ..extensions import db
        db.session.commit()
    return out


#: Single secrets kept in ``app_settings`` (label, key, vault path, field).
#: ONE list for migrate and scrub: two copies of it is how the alert-webhook
#: secret stayed out of both until 2026-10-15.
SETTING_SECRETS = (
    ("FortiAuthenticator shared secret", "auth.radius.secret_enc",
     "auth/fortiauthenticator", "shared_secret"),
    ("LDAP/AD bind password", "auth.ldap.bind_password_enc",
     "auth/ldap", "bind_password"),
    ("Alert webhook HMAC secret", "alerts.webhook.secret",
     "alerts/webhook", "secret"),
    ("Update feed token", "updates.feed.token_enc", "updates/feed", "token"),
    ("Package index token", "updates.index.token_enc", "updates/index", "token"),
)

_HOOK_PREFIX = "integrations.secret."


def _hook_path(name: str) -> str:
    return "hooks/%s" % name


_CONNECTION_PREFIX = "studio.connection.secret."


def _connection_path(name: str) -> str:
    return "studio/connections/%s" % name


_CONFLUENCE_PREFIX = "wiki.confluence.secret."


def _confluence_path(name: str) -> str:
    return "wiki/confluence/%s" % name


#: Secrets kept one ``app_settings`` row per name: (kind, key prefix, vault
#: path of a name). ONE list for migrate and scrub, like SETTING_SECRETS.
_PREFIXED_SECRETS = (
    ("hook-secret", _HOOK_PREFIX, _hook_path),
    ("connection-secret", _CONNECTION_PREFIX, _connection_path),
    ("confluence-secret", _CONFLUENCE_PREFIX, _confluence_path),
)


def _prefixed_secret_rows(kind, prefix, note):
    """(key, name, local plaintext) of every stored secret under *prefix*; an
    undecryptable row is reported through ``note`` and skipped."""
    rows = AppSetting.query.filter(AppSetting.key.like(prefix + "%")) \
        .order_by(AppSetting.key).all()
    for row in rows:
        if not row.key.startswith(prefix):     # LIKE treats _ and % as wildcards
            continue
        name = row.key[len(prefix):]
        try:
            local = encryption.decrypt(row.value) if row.value else ""
        except Exception as exc:  # noqa: BLE001
            note(kind, name, "failed", "local copy undecryptable: %s" % exc)
            continue
        if not local:
            note(kind, name, "skipped", "no value stored")
            continue
        yield row.key, name, local


def _hook_secret_rows(note):
    """(key, NAME, local plaintext) of every stored hook secret."""
    return _prefixed_secret_rows("hook-secret", _HOOK_PREFIX, note)


def scrub_local_copies(dry_run: bool = True) -> dict:
    """Replace every vault-backed local copy with the sentinel.

    This is the step that actually closes the ``.env`` exposure. Changing the
    mode only decides where the NEXT write goes; until this runs, the Fernet
    copy is still in the database and the key that decrypts it is still on the
    same disk, so nothing has moved.

    ``migrate_local_to_vault`` deliberately does not do this. Copying and
    destroying are different decisions, and only one of them is reversible.

    Refused unless the vault is authoritative. In ``mirror`` the local copy IS
    the documented fallback: removing it would silently turn the mode an
    operator chose for its safety net into vault-only.

    Every secret is READ BACK FROM THE VAULT and compared against the local
    plaintext before that plaintext is overwritten. A vault copy that is
    missing or different means the local one is the last working copy, so the
    row is left alone and reported as failed. Destroying the last copy of a
    credential is the one failure here that no later step can undo.
    """
    from ..models import Appliance
    from ..extensions import db

    out = {"dry_run": bool(dry_run), "scrubbed": 0, "failed": 0, "skipped": 0,
           "items": [], "ok": True}

    def note(kind, name, status, detail=""):
        out["items"].append({"kind": kind, "name": name, "status": status,
                             "detail": detail})
        if status == "scrubbed":
            out["scrubbed"] += 1
        elif status == "skipped":
            out["skipped"] += 1
        else:
            out["failed"] += 1
            out["ok"] = False

    if not authoritative():
        out["ok"] = False
        out["error"] = (
            "The vault is not the authoritative store. Set the mode to "
            "\u201cStore in the vault only\u201d before removing local copies.")
        return out

    for row in Appliance.query.order_by(Appliance.name).all():
        name = (row.name or "").strip()
        if not name:
            note("appliance", "(unnamed)", "skipped", "row has no name")
            continue
        try:
            local = encryption.decrypt(row.password_enc) if row.password_enc else ""
        except Exception as exc:  # noqa: BLE001
            note("appliance", name, "failed", "local copy undecryptable: %s" % exc)
            continue
        if not local:
            note("appliance", name, "skipped", "no local password stored")
            continue
        if local == VAULT_SENTINEL:
            note("appliance", name, "skipped", "already vault-owned")
            continue
        try:
            remote = (read(appliance_path(name)) or {}).get("password") or ""
        except VaultError as exc:
            note("appliance", name, "failed", "vault unreadable: %s" % exc)
            continue
        if not remote:
            note("appliance", name, "failed",
                 "no copy in the vault - the local one is the last one")
            continue
        if remote != local:
            note("appliance", name, "failed",
                 "the vault copy differs from the local one")
            continue
        if dry_run:
            note("appliance", name, "scrubbed", "would remove the local copy")
            continue
        row.password_enc = encryption.encrypt(VAULT_SENTINEL)
        db.session.add(row)
        db.session.commit()
        note("appliance", name, "scrubbed", "local copy replaced by the sentinel")

    # The separate SSH login: same rule, read back before destroying.
    for row in Appliance.query.order_by(Appliance.name).all():
        name = (row.name or "").strip()
        if not name or not getattr(row, "ssh_password_enc", None):
            continue
        try:
            local = encryption.decrypt(row.ssh_password_enc)
        except Exception as exc:  # noqa: BLE001
            note("appliance-ssh", name, "failed", "local copy undecryptable: %s" % exc)
            continue
        if local == VAULT_SENTINEL:
            note("appliance-ssh", name, "skipped", "already vault-owned")
            continue
        try:
            remote = (read(appliance_path(name)) or {}).get("ssh_password") or ""
        except VaultError as exc:
            note("appliance-ssh", name, "failed", "vault unreadable: %s" % exc)
            continue
        if remote != local:
            note("appliance-ssh", name, "failed",
                 "the vault copy is missing or differs - the local one is the last one")
            continue
        if dry_run:
            note("appliance-ssh", name, "scrubbed", "would remove the local copy")
            continue
        row.ssh_password_enc = encryption.encrypt(VAULT_SENTINEL)
        db.session.add(row)
        db.session.commit()
        note("appliance-ssh", name, "scrubbed", "local copy replaced by the sentinel")

    for label, key, path, field in SETTING_SECRETS:
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
        if not local:
            note("setting", label, "skipped", "not configured")
            continue
        try:
            remote = (read(path) or {}).get(field) or ""
        except VaultError as exc:
            note("setting", label, "failed", "vault unreadable: %s" % exc)
            continue
        if not remote:
            note("setting", label, "failed",
                 "no copy in the vault - the local one is the last one")
            continue
        if remote != local:
            note("setting", label, "failed",
                 "the vault copy differs from the local one")
            continue
        if dry_run:
            note("setting", label, "scrubbed", "would remove the local copy")
            continue
        AppSetting.set(key, encryption.encrypt(VAULT_SENTINEL))
        note("setting", label, "scrubbed", "local copy replaced by the sentinel")

    # Integration-hook and connection secrets: same rule, read back before destroying.
    for kind, prefix, path_of in _PREFIXED_SECRETS:
        for key, name, local in _prefixed_secret_rows(kind, prefix, note):
            if local == VAULT_SENTINEL:
                note(kind, name, "skipped", "already vault-owned")
                continue
            try:
                remote = (read(path_of(name)) or {}).get("value") or ""
            except VaultError as exc:
                note(kind, name, "failed", "vault unreadable: %s" % exc)
                continue
            if remote != local:
                note(kind, name, "failed",
                     "the vault copy is missing or differs - the local one is the last one")
                continue
            if dry_run:
                note(kind, name, "scrubbed", "would remove the local copy")
                continue
            AppSetting.set(key, encryption.encrypt(VAULT_SENTINEL))
            note(kind, name, "scrubbed", "local copy replaced by the sentinel")

    return out
