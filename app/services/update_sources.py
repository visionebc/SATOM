"""Where this installation looks for updates (Settings → General → Update sources).

Two sources, each set on its own and each optional:

* ``feed``  -- the system-upgrade feed (``latest.json``) that Software Update &
  HA reads to find and download the newest signed update package. Default: the
  public repository, or ``SATOM_UPGRADE_FEED`` when the node's environment sets
  it.
* ``index`` -- the Python package index the Libraries card checks and the
  privileged runner installs from. Default: pypi.org (and pip's own
  configuration on the node, for the install).

Either one may point at an internal pipeline or mirror, public (URL only) or
behind HTTP Basic (user + token). The token is a secret: it follows the vault
mode like every other credential (``secret_backend.SETTING_SECRETS``), is never
returned to the browser, and only travels to the host of the URL it belongs to.

Changing the source changes WHERE the bytes come from, never whether they are
trusted: an update package is still verified against the node's trust store,
and the Libraries card can only move the curated packages.

The settings live in ``app_settings``, which the HA standby receives by
streaming replication, so both nodes of a pair use the same sources.
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit

from ..models import AppSetting

FEED = "feed"
INDEX = "index"
KINDS = (FEED, INDEX)

LABELS = {FEED: "update feed", INDEX: "package index"}
#: Shown when no custom index is set. The install then uses pip's own default.
DEFAULT_INDEX_URL = "https://pypi.org/simple"

_K_URL = {FEED: "updates.feed.url", INDEX: "updates.index.url"}
_K_USER = {FEED: "updates.feed.user", INDEX: "updates.index.user"}
#: Fernet-encrypted at rest, or the vault sentinel. Listed in
#: ``secret_backend.SETTING_SECRETS`` so migrate/scrub cover them.
K_TOKEN = {FEED: "updates.feed.token_enc", INDEX: "updates.index.token_enc"}
VAULT_PATH = {FEED: "updates/feed", INDEX: "updates/index"}
VAULT_FIELD = "token"

MAX_URL = 500
MAX_USER = 128
MAX_TOKEN = 1024
_CTRL = re.compile(r"[\x00-\x1f\x7f]")


def _kind(kind: str) -> str:
    if kind not in KINDS:
        raise ValueError("unknown update source %r" % (kind,))
    return kind


def _get(key: str) -> str:
    return (AppSetting.get(key) or "").strip()


# ---- validation -------------------------------------------------------------
def url_problem(url: str) -> str:
    """Why ``url`` cannot be a source, or ``""``."""
    u = (url or "").strip()
    if not u:
        return ""
    if len(u) > MAX_URL:
        return "the URL is longer than %d characters" % MAX_URL
    if _CTRL.search(u) or " " in u:
        return "the URL contains spaces or control characters"
    try:
        parts = urlsplit(u)
        parts.port  # noqa: B018 -- raises on a bad port
    except ValueError as exc:
        return "the URL cannot be parsed: %s" % exc
    if parts.scheme != "https":
        return "only https:// sources are accepted"
    if not parts.hostname:
        return "the URL names no host"
    if parts.username or parts.password or "@" in parts.netloc:
        return ("put the user and token in their own fields, not in the URL "
                "(a URL is logged and shown; a token must not be)")
    if parts.query or parts.fragment:
        return "the URL must not carry a query string or fragment"
    return ""


def user_problem(user: str) -> str:
    u = user or ""
    if len(u) > MAX_USER:
        return "the user is longer than %d characters" % MAX_USER
    if _CTRL.search(u) or ":" in u or " " in u:
        return "the user must not contain ':', spaces or control characters"
    return ""


def token_problem(token: str) -> str:
    t = token or ""
    if len(t) > MAX_TOKEN:
        return "the token is longer than %d characters" % MAX_TOKEN
    if _CTRL.search(t):
        return "the token contains control characters"
    return ""


def display_url(url: str) -> str:
    """``host/path`` of a source for status lines (no scheme, no slash noise)."""
    try:
        p = urlsplit(url or "")
    except ValueError:
        return url or ""
    host = p.hostname or ""
    if p.port:
        host += ":%d" % p.port
    return (host + p.path).rstrip("/")


# ---- the token (a secret) ---------------------------------------------------
def token_state(kind: str) -> tuple:
    """``(token, problem)``: the token (``""`` if none can be used) and why a
    CONFIGURED token could not be read. Vault first, then the local copy, the
    same order as every other setting secret."""
    _kind(kind)
    raw = _get(K_TOKEN[kind])
    if not raw:
        return "", ""
    from . import secret_backend as sb
    vault_err = ""
    try:
        vaulted = sb.get_field(VAULT_PATH[kind], VAULT_FIELD)
    except Exception as exc:  # noqa: BLE001 -- vault-only and unreadable
        vaulted, vault_err = "", str(exc) or exc.__class__.__name__
    if vaulted:
        return vaulted, ""
    try:
        from .encryption import decrypt
        local = decrypt(raw) or ""
    except Exception:  # noqa: BLE001
        return "", "the local copy of the token could not be decrypted (FERNET_KEY changed?)"
    if local == sb.VAULT_SENTINEL:
        return "", ("the token is stored in the vault, which could not be read: %s"
                    % (vault_err or "no value at %s" % VAULT_PATH[kind]))
    return local, ""


def set_token(kind: str, value: str) -> None:
    """Store (or clear, with ``""``) the token where the vault mode says.
    Raises ``ValueError`` when the vault is the only store and refuses it."""
    _kind(kind)
    from .encryption import encrypt
    from . import secret_backend as sb
    key, path = K_TOKEN[kind], VAULT_PATH[kind]
    if not value:
        AppSetting.set(key, "")
        try:
            if sb.active():
                sb.delete(path)
        except Exception:  # noqa: BLE001 -- the local copy is gone already
            pass
        return
    stored = False
    try:
        stored = sb.put_field(path, VAULT_FIELD, value)
    except Exception:  # noqa: BLE001
        if sb.authoritative():
            raise ValueError("the vault is the only secret store and refused the "
                             "write; the %s token was not saved" % LABELS[kind])
    if stored and sb.authoritative():
        AppSetting.set(key, encrypt(sb.VAULT_SENTINEL))
    else:
        AppSetting.set(key, encrypt(value))


# ---- reading the configuration ---------------------------------------------
def _default_url(kind: str) -> str:
    if kind == FEED:
        from .update_package_service import feed
        return feed.feed_url()
    return DEFAULT_INDEX_URL


def config(kind: str) -> dict:
    """What the card shows. Never the token itself."""
    _kind(kind)
    url = _get(_K_URL[kind])
    user = _get(_K_USER[kind])
    has_token = bool(_get(K_TOKEN[kind]))
    problem = ""
    if user and has_token:
        problem = token_state(kind)[1]
    elif user:
        problem = "a user is set but no token is stored"
    default = _default_url(kind)
    return {
        "kind": kind,
        "custom": bool(url),
        "url": url,
        "default_url": default,
        "effective_url": url or default,
        "source": display_url(url or default),
        "auth": bool(user),
        "user": user,
        "has_token": has_token,
        "url_problem": url_problem(url),
        "problem": problem,
    }


def state() -> dict:
    return {k: config(k) for k in KINDS}


def target(kind: str) -> dict:
    """What a fetch or an install should use right now.

    ``url`` is the custom source, or the default (``None`` for the index: the
    install then leaves pip to its own configuration). ``auth`` is
    ``(host, user, token)`` or ``None``. ``problem`` is set when a configured
    source cannot be used as configured (a bad URL, an unreadable token) --
    callers must refuse rather than quietly fall back to the default, which
    would fetch from somewhere the operator did not choose.
    """
    c = config(kind)
    url = c["url"] or (c["default_url"] if kind == FEED else None)
    out = {"kind": kind, "custom": c["custom"], "url": url, "auth": None,
           "source": c["source"], "problem": c["url_problem"] or c["problem"]}
    if out["problem"] or not c["custom"] or not c["user"]:
        return out
    token = token_state(kind)[0]
    out["auth"] = ((urlsplit(c["url"]).hostname or "").lower(), c["user"], token)
    return out


# ---- saving -----------------------------------------------------------------
def save(kind: str, *, custom: bool, url: str = "", auth: bool = False,
         user: str = "", token: str = "") -> list:
    """Store one source. Returns a list of problems (empty on success); on a
    problem NOTHING is written. A blank ``token`` with ``auth`` keeps the
    stored one, so the form never has to show it."""
    _kind(kind)
    url = (url or "").strip() if custom else ""
    user = (user or "").strip() if (custom and auth) else ""
    token = token or ""
    errors = []
    if custom:
        if not url:
            errors.append("a custom source needs a URL")
        else:
            p = url_problem(url)
            if p:
                errors.append(p)
    if custom and auth:
        if not user:
            errors.append("authentication needs a user")
        p = user_problem(user) or token_problem(token)
        if p:
            errors.append(p)
        if not token and not _get(K_TOKEN[kind]):
            errors.append("authentication needs a token")
    if errors:
        return errors
    if custom and auth and token:
        set_token(kind, token)          # may raise ValueError (vault-only refused)
    elif not (custom and auth):
        set_token(kind, "")
    AppSetting.set(_K_URL[kind], url)
    AppSetting.set(_K_USER[kind], user)
    return []


# ---- testing a source before (or after) saving it ---------------------------
def _form_target(kind: str, *, custom: bool, url: str, auth: bool, user: str,
                 token: str) -> dict:
    """The target the form describes, without saving it. A blank token with
    authentication means "the stored one"."""
    if not custom:
        url = _default_url(kind)
        return {"url": url, "auth": None, "problem": ""}
    url = (url or "").strip()
    problem = url_problem(url) or ("" if url else "a custom source needs a URL")
    if problem or not auth:
        return {"url": url, "auth": None, "problem": problem}
    user = (user or "").strip()
    problem = user_problem(user) or token_problem(token or "")
    if not user:
        problem = problem or "authentication needs a user"
    if not token:
        token, tproblem = token_state(kind)
        problem = problem or tproblem or ("" if token else "authentication needs a token")
    return {"url": url, "problem": problem,
            "auth": ((urlsplit(url).hostname or "").lower(), user, token)}


def test(kind: str, **form) -> dict:
    """Reach the source the form describes and say what it offers."""
    _kind(kind)
    t = _form_target(kind, **form)
    if t["problem"]:
        return {"ok": False, "error": t["problem"]}
    if kind == FEED:
        from .update_package_service import feed
        try:
            doc = feed.fetch_feed(t["url"], auth=t["auth"])
        except feed.FeedError as exc:
            return {"ok": False, "error": str(exc)}
        return {"ok": True, "source": display_url(t["url"]), "version": doc["version"],
                "package": doc["package"]["name"],
                "message": "the feed offers %s (%s)" % (doc["version"], doc["package"]["name"])}
    from . import library_updates as libupd
    probe = "Flask"
    res = libupd.probe_index(t["url"], t["auth"], probe)
    if not res["ok"]:
        return {"ok": False, "error": res["error"]}
    return {"ok": True, "source": display_url(t["url"]), "package": probe,
            "latest": res["latest"],
            "message": "the index answers: latest %s is %s" % (probe, res["latest"])}
