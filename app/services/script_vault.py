"""Script Library credentials in the vault (web side only).

Credentials a script declares (``FGT_ADMIN`` = username + password, ``API_KEY``
= one value) live in the configured vault (OpenBao / HashiCorp Vault, KV v2)
at ``<mount>/scripts/<slug>/<NAME>``. Never in the SATOM database, never on
disk on the node. Without a vault the feature is off: credentials cannot be
set and a script that declares one refuses to queue.

HOW A RUN GETS THEM -- response wrapping
    When a run is queued, this module asks the vault for a WRAPPED read of
    each declared credential: the vault answers with a single-use token that
    unwraps to the secret, valid for ``WRAP_TTL`` seconds. Only those tokens go
    into the queued request. The runner (``script_runner``, no database, no
    vault login of its own) unwraps them at the start of the run. So:
      * no secret is ever written to the node's disk;
      * the runner holds no standing credential that could be stolen;
      * a token used by anyone else first makes the run FAIL, visibly
        ("already used or expired") -- tampering shows instead of passing.

Write-only from the browser: the page shows "stored" / "not set" (from the KV
metadata, the values are never read back for display) and a form to replace
the value.
"""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.request

from . import secret_backend as sb
from .script_library import ScriptError, validate_slug

WRAP_TTL = 900            # seconds a queued run has to start
_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
KINDS = ("userpass", "secret")
MAX_VALUE = 8192


def available() -> bool:
    try:
        return bool(sb.active())
    except Exception:  # noqa: BLE001
        return False


def path(slug: str, name: str) -> str:
    validate_slug(slug)
    if not _NAME_RE.match(name or ""):
        raise ScriptError("invalid credential name %r" % name)
    return "scripts/%s/%s" % (slug, name)


def _require():
    if not available():
        raise ScriptError("no vault is configured: script credentials are stored "
                          "only in the vault (Settings > Vault)")


def _metadata_exists(p: str) -> bool:
    cfg = sb.config(reveal=False)
    tok = sb._token(cfg)
    try:
        res = sb._request(cfg, "GET", "%s/metadata/%s" % (cfg["mount"], p), token=tok)
    except sb.VaultError as exc:
        if "HTTP 404" in str(exc):
            return False
        raise
    data = res.get("data") or {}
    cur = str(data.get("current_version") or "")
    ver = (data.get("versions") or {}).get(cur) or {}
    # a soft-deleted latest version is "not set"
    return bool(cur) and not ver.get("deletion_time") and not ver.get("destroyed")


def status(slug: str, credentials: list[dict]) -> dict:
    """{NAME: "stored" | "not set" | "error: ..."} or {} when no vault."""
    if not available():
        return {}
    out = {}
    for c in credentials or []:
        try:
            out[c["name"]] = "stored" if _metadata_exists(path(slug, c["name"])) else "not set"
        except Exception as exc:  # noqa: BLE001
            out[c["name"]] = "error: %s" % str(exc)[:120]
    return out


def store(slug: str, cred: dict, values: dict) -> None:
    """Replace the stored value(s) of one declared credential."""
    _require()
    if cred.get("kind") == "userpass":
        data = {"username": str(values.get("username") or ""),
                "password": str(values.get("password") or "")}
        if not data["password"]:
            raise ScriptError("a password is required")
    else:
        data = {"value": str(values.get("value") or "")}
        if not data["value"]:
            raise ScriptError("a value is required")
    if any(len(v) > MAX_VALUE for v in data.values()):
        raise ScriptError("value too long")
    sb.write(path(slug, cred["name"]), data)


def forget(slug: str, names: list[str]) -> None:
    if not available():
        return
    for n in names:
        try:
            sb.delete(path(slug, n))
        except Exception:  # noqa: BLE001 -- deleting a script must not stall on this
            pass


def _vault_info(cfg: dict) -> dict:
    ca = (cfg.get("ca_cert") or "").strip()
    if ca and not ca.startswith("-----BEGIN"):
        # A path (often under pki/, which the runner's unit cannot read):
        # hand over the PEM itself. A CA certificate is public.
        try:
            with open(ca, encoding="utf-8") as fh:
                ca = fh.read()
        except OSError:
            ca = ""
    return {"addr": cfg["addr"], "namespace": cfg.get("namespace") or "",
            "verify_tls": bool(cfg.get("verify_tls", True)), "ca_cert": ca,
            "timeout": float(cfg.get("timeout") or 10)}


def _wrapped_read(cfg: dict, tok: str, kv_path: str) -> str | None:
    """Single-use wrapping token for one KV v2 path, or None if absent."""
    url = "%s/v1/%s/data/%s" % (cfg["addr"], cfg["mount"], kv_path)
    req = urllib.request.Request(url, method="GET")
    req.add_header("X-Vault-Token", tok)
    req.add_header("X-Vault-Wrap-TTL", str(WRAP_TTL))
    if cfg.get("namespace"):
        req.add_header("X-Vault-Namespace", cfg["namespace"])
    try:
        with urllib.request.urlopen(req, context=sb._ssl_context(cfg),
                                    timeout=cfg["timeout"]) as resp:
            res = json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise ScriptError("vault refused %s: HTTP %s" % (kv_path, exc.code))
    except Exception as exc:  # noqa: BLE001
        raise ScriptError("vault unreachable for %s: %s" % (kv_path, exc))
    return (res.get("wrap_info") or {}).get("token") or None


def wrap_path(kv_path: str) -> tuple[str | None, dict]:
    """(single-use token, vault info) for an arbitrary script-owned path --
    the password values of a saved run."""
    if not kv_path.startswith(("scripts/", "scripts-saved/")):
        raise ScriptError("refusing to wrap %r" % kv_path)
    _require()
    cfg = sb.config(reveal=False)
    return _wrapped_read(cfg, sb._token(cfg), kv_path), _vault_info(cfg)


def wrap_for_run(slug: str, credentials: list[dict]) -> tuple[dict, list[str], dict]:
    """({NAME: wrapping token}, [missing names], vault connection info).

    Raises ScriptError when the script declares credentials and there is no
    vault. A credential that is not set is reported as missing; the run can
    still be queued (the script's ``secret()`` raises for it)."""
    names = [c["name"] for c in credentials or []]
    if not names:
        return {}, [], {}
    _require()
    cfg = sb.config(reveal=False)
    tok = sb._token(cfg)
    wrapped, missing = {}, []
    for n in names:
        wt = _wrapped_read(cfg, tok, path(slug, n))
        if wt is None:
            missing.append(n)
        else:
            wrapped[n] = wt
    info = _vault_info(cfg)
    return wrapped, missing, info
