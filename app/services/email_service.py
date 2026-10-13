"""Email / SMTP delivery service (configurable from Settings → Email).

The desktop app has no mailer; the web app needs one so the Automation subsystem
can actually SEND a change-request maintenance notice instead of only rendering it
(``change_requests.maintenance_notice`` + the "mark notified" step).

Design mirrors the rest of the web settings:

* All configuration lives in the ``app_settings`` table (``AppSetting.get/set``)
  so every gunicorn worker and admin share ONE source of truth — exactly like
  ``settings_store``.
* The SMTP **password is the only secret** and is stored Fernet-encrypted
  (``services.encryption``), never returned to the template in plaintext (the UI
  gets a ``has_password`` flag; a blank password field keeps the stored one — the
  same blank-keeps-existing rule the Git token uses).
* Transport is stdlib ``smtplib`` + ``ssl`` + ``email.message.EmailMessage`` — no
  new dependency, works offline / air-gapped.

Two deployment shapes the operator chooses between (your "local or third-party"):

* ``mode = "local"``  — a local MTA on ``localhost:25``, no auth, no TLS (the box
  relays through Postfix/sendmail). Host/port/security/auth are forced to the
  local defaults so it "just works".
* ``mode = "smtp"``   — an external provider: host + port + transport security
  (``none`` | ``starttls`` | ``ssl``) + optional username/password, plus a
  *verify certificate* toggle for internal self-signed servers (your "with or
  without security").
"""
from __future__ import annotations

import os
import re
import shutil
import smtplib
import ssl
import subprocess
from email.message import EmailMessage
from email.utils import formataddr, formatdate, make_msgid, parseaddr

from ..models import AppSetting
from . import encryption

# ---- keys -----------------------------------------------------------------
K_ENABLED = "email.enabled"            # "1" / "0"
K_MODE = "email.mode"                  # local | smtp
K_HOST = "email.host"
K_PORT = "email.port"
K_SECURITY = "email.security"          # none | starttls | ssl
K_TLS_VERIFY = "email.tls_verify"      # "1" / "0"
K_AUTH = "email.auth"                  # "1" / "0"
K_USERNAME = "email.username"
K_PASSWORD_ENC = "email.password_enc"  # Fernet token
K_FROM_ADDR = "email.from_addr"
K_FROM_NAME = "email.from_name"
K_DEFAULT_TO = "email.default_to"      # comma/newline separated
K_TIMEOUT = "email.timeout"            # seconds

MODES = ("local", "smtp")
SECURITIES = ("none", "starttls", "ssl")

# Default port per transport (used when the operator leaves Port blank).
_DEFAULT_PORT = {"none": 25, "starttls": 587, "ssl": 465}

DEFAULTS = {
    K_ENABLED: "0",
    K_MODE: "local",
    K_HOST: "localhost",
    K_PORT: "25",
    K_SECURITY: "none",
    K_TLS_VERIFY: "1",
    K_AUTH: "0",
    K_USERNAME: "",
    K_FROM_ADDR: "",
    K_FROM_NAME: "SATOM",
    K_DEFAULT_TO: "",
    K_TIMEOUT: "20",
}

_SPLIT_RE = re.compile(r"[,;\n]+")


# ---- low-level ------------------------------------------------------------
def _get(key: str) -> str:
    val = AppSetting.get(key)
    return DEFAULTS.get(key, "") if val is None else val


def _to_int(val, fallback: int) -> int:
    try:
        return int(str(val).strip())
    except (TypeError, ValueError):
        return fallback


def _has_password() -> bool:
    return bool(AppSetting.get(K_PASSWORD_ENC))


def _raw_password() -> str:
    """Decrypt the stored SMTP password (``""`` if none / undecryptable)."""
    token = AppSetting.get(K_PASSWORD_ENC)
    if not token:
        return ""
    try:
        return encryption.decrypt(token)
    except Exception:  # noqa: BLE001 — bad key / corrupt token → behave as unset
        return ""


def parse_recipients(value) -> list[str]:
    """Split a comma/semicolon/newline string (or list) into clean addresses."""
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        parts = []
        for v in value:
            parts.extend(_SPLIT_RE.split(str(v)))
    else:
        parts = _SPLIT_RE.split(str(value))
    out: list[str] = []
    for p in parts:
        addr = parseaddr(p.strip())[1]
        if addr and addr not in out:
            out.append(addr)
    return out


# ---- config (read) --------------------------------------------------------
def config(*, reveal_password: bool = False) -> dict:
    """The full email configuration. The password is NEVER included in plaintext
    unless ``reveal_password`` (used internally by the sender); the template gets
    only ``has_password``."""
    mode = _get(K_MODE) if _get(K_MODE) in MODES else "local"
    if mode == "local":
        # Local relay: fixed, simple, no auth/TLS — the operator picks "local"
        # precisely so they don't have to think about it.
        cfg = {
            "enabled": _get(K_ENABLED) == "1",
            "mode": "local",
            "host": "localhost",
            "port": _to_int(_get(K_PORT), 25) or 25,
            "security": "none",
            "tls_verify": True,
            "auth": False,
            "username": "",
            "from_addr": _get(K_FROM_ADDR),
            "from_name": _get(K_FROM_NAME),
            "default_to": _get(K_DEFAULT_TO),
            "timeout": _to_int(_get(K_TIMEOUT), 20),
            "has_password": False,
        }
    else:
        security = _get(K_SECURITY) if _get(K_SECURITY) in SECURITIES else "none"
        cfg = {
            "enabled": _get(K_ENABLED) == "1",
            "mode": "smtp",
            "host": _get(K_HOST),
            "port": _to_int(_get(K_PORT), _DEFAULT_PORT[security]),
            "security": security,
            "tls_verify": _get(K_TLS_VERIFY) != "0",
            "auth": _get(K_AUTH) == "1",
            "username": _get(K_USERNAME),
            "from_addr": _get(K_FROM_ADDR),
            "from_name": _get(K_FROM_NAME),
            "default_to": _get(K_DEFAULT_TO),
            "timeout": _to_int(_get(K_TIMEOUT), 20),
            "has_password": _has_password(),
        }
    if reveal_password:
        cfg["password"] = _raw_password() if cfg.get("auth") else ""
    return cfg


def is_configured() -> bool:
    """True if email is enabled AND has enough to attempt a send."""
    cfg = config()
    if not cfg["enabled"]:
        return False
    if not cfg["from_addr"]:
        return False
    if cfg["mode"] == "smtp" and not cfg["host"]:
        return False
    return True


# ---- config (write) -------------------------------------------------------
def save_config(form) -> None:
    """Persist the email settings from a Flask ``request.form`` (or any mapping
    exposing ``.get`` / ``.getlist``). The password is encrypted; a blank password
    field KEEPS the stored one (blank-keeps-existing, like the Git token)."""
    def g(key, default=""):
        return (form.get(key, default) or "").strip()

    mode = g("mode", "local")
    mode = mode if mode in MODES else "local"
    security = g("security", "none")
    security = security if security in SECURITIES else "none"

    AppSetting.set(K_ENABLED, "1" if form.get("enabled") in ("1", "on", "true") else "0")
    AppSetting.set(K_MODE, mode)
    AppSetting.set(K_FROM_ADDR, g("from_addr"))
    AppSetting.set(K_FROM_NAME, g("from_name") or "SATOM")
    AppSetting.set(K_DEFAULT_TO, g("default_to"))
    AppSetting.set(K_TIMEOUT, str(max(5, min(120, _to_int(g("timeout"), 20)))))

    if mode == "local":
        AppSetting.set(K_HOST, "localhost")
        AppSetting.set(K_PORT, str(_to_int(g("port"), 25) or 25))
        AppSetting.set(K_SECURITY, "none")
        AppSetting.set(K_AUTH, "0")
        AppSetting.set(K_TLS_VERIFY, "1")
    else:
        AppSetting.set(K_HOST, g("host"))
        AppSetting.set(K_PORT, str(_to_int(g("port"), _DEFAULT_PORT[security])))
        AppSetting.set(K_SECURITY, security)
        AppSetting.set(K_TLS_VERIFY, "1" if form.get("tls_verify") in ("1", "on", "true") else "0")
        auth_on = form.get("auth") in ("1", "on", "true")
        AppSetting.set(K_AUTH, "1" if auth_on else "0")
        AppSetting.set(K_USERNAME, g("username"))
        # Password: only overwrite when a new value is supplied; blank keeps it.
        new_pw = form.get("password", "")
        if new_pw:
            AppSetting.set(K_PASSWORD_ENC, encryption.encrypt(new_pw))
        elif not auth_on:
            # Auth turned off → forget the stored secret.
            AppSetting.set(K_PASSWORD_ENC, "")


# ---- send -----------------------------------------------------------------
def _build_message(cfg: dict, to: list[str], subject: str,
                   body: str, html: str | None) -> EmailMessage:
    msg = EmailMessage()
    from_addr = cfg["from_addr"] or (cfg["username"] if cfg.get("username") else "")
    msg["From"] = formataddr((cfg.get("from_name") or "SATOM", from_addr))
    msg["To"] = ", ".join(to)
    msg["Subject"] = subject
    # RFC 5322 requires Date; Gmail refuses a message without Message-ID
    # ("550 5.7.1 Messages missing a valid Message-ID header are not
    # accepted"). A local Postfix used to add both on our behalf, which hid
    # the gap; a provider or a direct MX hand-off does not.
    msg["Date"] = formatdate(localtime=True)
    domain = from_addr.rpartition("@")[2] if "@" in from_addr else None
    msg["Message-ID"] = make_msgid(domain=domain or None)
    msg.set_content(body or "")
    if html:
        msg.add_alternative(html, subtype="html")
    return msg


def _ssl_context(verify: bool) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def send_email(to, subject: str, body: str, *, html: str | None = None,
               cfg: dict | None = None, force: bool = False) -> dict:
    """Send one message. Returns ``{ok: bool, detail: str, recipients: [...]}``.

    Never raises — connectivity/auth/TLS errors are caught and reported in
    ``detail`` so callers (the test button, the CR notify step) can surface them
    without a 500.

    Honours "Enable email sending": when it is off nothing is attempted
    (alerts, bug reports, Certificate Manager, CR notifications, password
    reset). Only the Settings "Send test email" button passes ``force``."""
    cfg = cfg or config(reveal_password=True)
    if not force and not cfg.get("enabled", True):
        return {"ok": False, "detail": "Email sending is disabled (Settings → Email & Alerts).",
                "recipients": []}
    recipients = parse_recipients(to) or parse_recipients(cfg.get("default_to"))
    if not recipients:
        return {"ok": False, "detail": "No recipient address.", "recipients": []}
    if not cfg.get("from_addr") and not cfg.get("username"):
        return {"ok": False, "detail": "No 'From' address configured.", "recipients": recipients}
    host = cfg["host"] or "localhost"
    port = int(cfg.get("port") or _DEFAULT_PORT.get(cfg.get("security", "none"), 25))
    timeout = float(cfg.get("timeout") or 20)
    security = cfg.get("security", "none")

    msg = _build_message(cfg, recipients, subject, body, html)
    try:
        if security == "ssl":
            ctx = _ssl_context(cfg.get("tls_verify", True))
            server = smtplib.SMTP_SSL(host, port, timeout=timeout, context=ctx)
        else:
            server = smtplib.SMTP(host, port, timeout=timeout)
        try:
            server.ehlo()
            if security == "starttls":
                server.starttls(context=_ssl_context(cfg.get("tls_verify", True)))
                server.ehlo()
            if cfg.get("auth") and cfg.get("username"):
                server.login(cfg["username"], cfg.get("password", ""))
            server.send_message(msg)
        finally:
            try:
                server.quit()
            except Exception:  # noqa: BLE001 — already sent; closing is best-effort
                pass
    except smtplib.SMTPAuthenticationError as exc:
        return {"ok": False, "detail": f"Authentication failed: {exc}", "recipients": recipients}
    except (smtplib.SMTPException, ssl.SSLError, OSError) as exc:
        return {"ok": False, "detail": f"{type(exc).__name__}: {exc}", "recipients": recipients}

    return {"ok": True,
            "detail": f"Sent to {', '.join(recipients)} via {host}:{port} ({security}).",
            "recipients": recipients,
            "deliverability": deliverability(cfg)}


# ---- deliverability -------------------------------------------------------
# "Sent" only means the next hop took the message. Whether the recipient's
# filter trusts it is a separate question, and the one an operator cannot see
# from here: an alert in the spam folder is an alert nobody read. When we can
# PROVE the hand-off is unsigned, that is reported as an error next to every
# successful send, so "delivered" never reads as "received".

#: The web worker's PATH under systemd does not always include /usr/sbin.
_POSTCONF = ("/usr/sbin/postconf", "/usr/bin/postconf")

SPAM_RISK_DIRECT_MX = (
    "Delivered straight to the recipient's mail server with no DKIM "
    "signature (local Postfix: no relayhost, no signing milter). The message "
    "is authenticated by SPF at most, from this node's own address, so "
    "Gmail, Outlook and others may file it as spam. Fix: Settings -> Email "
    "-> External SMTP server with a provider account, or a relayhost / DKIM "
    "milter on this node.")


def _postconf(*keys: str) -> dict | None:
    """``{key: value}`` from the local Postfix, or None if it cannot be read."""
    exe = (next((p for p in _POSTCONF if os.path.exists(p)), None)
           or shutil.which("postconf"))
    if not exe:
        return None
    try:
        out = subprocess.run([exe, "-h", *keys], capture_output=True,
                             text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return None
    vals = out.stdout.splitlines()
    if out.returncode != 0 or len(vals) != len(keys):
        return None
    return dict(zip(keys, (v.strip() for v in vals)))


def deliverability(cfg: dict | None = None) -> dict:
    """Will the recipient's spam filter trust what this node hands over?

    ``{"ok": True|False|None, "detail": str}``. ``False`` is an ERROR: the
    path is proven unsigned (local Postfix delivering straight to the MX).
    ``None`` means the local MTA could not be inspected. An external SMTP
    provider, or a local MTA that relays or signs, is ``True`` — the signing
    is then the provider's job, and we do not claim to have checked it."""
    cfg = cfg or config()
    if cfg.get("mode") != "local":
        return {"ok": True, "detail": ""}
    pc = _postconf("relayhost", "smtpd_milters", "non_smtpd_milters")
    if pc is None:
        return {"ok": None, "detail": "The local MTA is not Postfix or cannot "
                                      "be inspected; deliverability unknown."}
    if pc["relayhost"]:
        return {"ok": True, "detail": "Relayed via %s." % pc["relayhost"]}
    if pc["smtpd_milters"] or pc["non_smtpd_milters"]:
        return {"ok": True, "detail": "A mail filter (milter) is configured "
                                      "on the local MTA."}
    return {"ok": False, "detail": SPAM_RISK_DIRECT_MX}


def send_test(to: str = "") -> dict:
    """Send a canned test message (used by the Settings 'Send test email' button)."""
    cfg = config(reveal_password=True)
    recipients = parse_recipients(to) or parse_recipients(cfg.get("default_to"))
    if not recipients:
        return {"ok": False, "detail": "Enter a recipient (or set a default recipient).",
                "recipients": []}
    body = ("This is a test message from SATOM.\n\n"
            "If you received this, your email settings are working.\n")
    return send_email(recipients,
                      "SATOM — test email", body, cfg=cfg, force=True)


__all__ = [
    "config", "is_configured", "save_config", "send_email", "send_test",
    "deliverability", "parse_recipients", "MODES", "SECURITIES", "DEFAULTS",
]
