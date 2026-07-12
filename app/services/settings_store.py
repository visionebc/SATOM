"""Centralised, DB-backed application settings (key/value in ``AppSetting``).

The desktop app keeps these in ``config.json``; the multi-user web app keeps
them in the ``app_settings`` table (``AppSetting.get/set``) so every gunicorn
worker and every admin share ONE source of truth. The previous Settings view
wrote to ``current_app.config`` — per-worker, in-memory, lost on restart — which
is why nothing persisted. JSON-encoded values cover the structured sections
(naming overrides, classification catalogs, network segments), mirroring the
desktop's ``cfg.naming`` / ``cfg.segments`` / classification catalogs.
"""
from __future__ import annotations

import json
from typing import Any

from ..models import AppSetting

# ---- keys -----------------------------------------------------------------
K_APP_NAME = "general.app_name"
K_DEFAULT_KIND = "general.default_kind"
K_SESSION_TIMEOUT = "general.session_timeout"      # minutes
K_POLL_INTERVAL = "general.poll_interval"          # seconds
K_SHOW_RAW = "general.show_raw_config"             # "1" / "0"
K_LOG_LEVELS = "general.log_levels"                # JSON list
K_NAMING = "naming.scheme"                          # JSON dict of overrides
K_CLS_PREFIX = "classification."                    # + zones|lines|departments -> JSON list
K_SEGMENTS = "network.segments"                     # JSON list of dicts
K_IP_WHITELIST = "access.ip_whitelist"              # JSON list of {ip, note}
K_ALLOWED_USERS = "access.allowed_users"            # JSON list of usernames
K_TIMEZONE = "general.timezone"                     # IANA tz name, e.g. Europe/Zurich
K_LOG_FORMAT = "general.log_format"                 # plain | detailed | json
K_ENV_MODE = "general.env_mode"                     # production | development

LOG_LEVELS_ALL = ["DEBUG", "INFO", "WARNING", "ERROR"]
ENV_MODES = ("production", "development")
LOG_FORMATS = ["plain", "detailed", "json"]
DEFAULT_TIMEZONE = "Europe/Zurich"
CLASSIFICATION_KINDS = ("zones", "lines", "departments")
SEGMENT_FIELDS = ("name", "zone", "line", "department", "cidr", "interface", "gateway", "note")

DEFAULTS = {
    K_APP_NAME: "OFortMAut",
    K_DEFAULT_KIND: "FortiWeb",
    K_SESSION_TIMEOUT: "60",
    K_POLL_INTERVAL: "30",
    K_SHOW_RAW: "0",
    K_TIMEZONE: DEFAULT_TIMEZONE,
    K_LOG_FORMAT: "plain",
    K_ENV_MODE: "development",
}


def env_mode() -> str:
    """Deployment environment: 'production' or 'development'. Drives the
    PROD/DEV badge shown in the top bar and the ADOM (product) picker. Stored in
    the replicated app_settings table, so it is set once on the primary and both
    HA nodes agree."""
    val = (get_str(K_ENV_MODE) or "development").strip().lower()
    return val if val in ENV_MODES else "development"


def save_env_mode(mode: str) -> None:
    mode = (mode or "").strip().lower()
    set_str(K_ENV_MODE, mode if mode in ENV_MODES else "development")


# ---- low-level ------------------------------------------------------------
def get_str(key: str, default: str | None = None) -> str | None:
    val = AppSetting.get(key)
    if val is None:
        return DEFAULTS.get(key, default)
    return val


def set_str(key: str, value: Any) -> None:
    AppSetting.set(key, "" if value is None else str(value))


def get_json(key: str, default: Any) -> Any:
    raw = AppSetting.get(key)
    if not raw:
        return default
    try:
        return json.loads(raw)
    except (ValueError, TypeError):
        return default


def set_json(key: str, value: Any) -> None:
    AppSetting.set(key, json.dumps(value))


def _to_int(val: Any, fallback: int) -> int:
    try:
        return int(val)
    except (TypeError, ValueError):
        return fallback


def _valid_tz(name: Any) -> str:
    name = (str(name).strip() if name else "")
    if not name:
        return DEFAULT_TIMEZONE
    try:
        from zoneinfo import ZoneInfo
        ZoneInfo(name)  # raises if unknown
        return name
    except Exception:
        return DEFAULT_TIMEZONE


def timezones() -> list[str]:
    """Sorted IANA timezone names for the Settings dropdown."""
    try:
        from zoneinfo import available_timezones
        names = sorted(available_timezones())
        return names or [DEFAULT_TIMEZONE]
    except Exception:
        return [DEFAULT_TIMEZONE, "UTC", "America/Mexico_City",
                "America/New_York", "Europe/London", "Europe/Zurich"]


# ---- General --------------------------------------------------------------
def general() -> dict[str, Any]:
    return {
        "app_name": get_str(K_APP_NAME),
        "default_kind": get_str(K_DEFAULT_KIND),
        "session_timeout": _to_int(get_str(K_SESSION_TIMEOUT), 60),
        "poll_interval": _to_int(get_str(K_POLL_INTERVAL), 30),
        "show_raw_config": get_str(K_SHOW_RAW) == "1",
        "log_levels": [lv for lv in get_json(K_LOG_LEVELS, LOG_LEVELS_ALL) if lv in LOG_LEVELS_ALL],
        "timezone": _valid_tz(get_str(K_TIMEZONE)),
        "log_format": (get_str(K_LOG_FORMAT) or "plain") if (get_str(K_LOG_FORMAT) or "plain") in LOG_FORMATS else "plain",
        "env_mode": env_mode(),
    }


def save_general(app_name: str, default_kind: str, session_timeout: Any,
                 poll_interval: Any, show_raw_config: bool,
                 log_levels: list[str], timezone: str = "",
                 log_format: str = "plain", env_mode: str = "") -> None:
    set_str(K_APP_NAME, (app_name or "OFortMAut").strip())
    set_str(K_DEFAULT_KIND, default_kind if default_kind in ("FortiWeb", "FortiWeb-Cloud", "FortiADC") else "FortiWeb")
    set_str(K_SESSION_TIMEOUT, max(5, min(1440, _to_int(session_timeout, 60))))
    set_str(K_POLL_INTERVAL, max(10, min(3600, _to_int(poll_interval, 30))))
    set_str(K_SHOW_RAW, "1" if show_raw_config else "0")
    set_json(K_LOG_LEVELS, [lv for lv in log_levels if lv in LOG_LEVELS_ALL] or ["INFO", "WARNING", "ERROR"])
    set_str(K_TIMEZONE, _valid_tz(timezone))
    set_str(K_LOG_FORMAT, log_format if log_format in LOG_FORMATS else "plain")
    if env_mode:
        save_env_mode(env_mode)


# ---- Naming ---------------------------------------------------------------
def _naming_key(product: str = "fortiweb") -> str:
    # FortiWeb keeps the original key for backward compatibility with already
    # saved overrides; other products are namespaced under it.
    return K_NAMING if product == "fortiweb" else f"{K_NAMING}.{product}"


def naming_overrides(product: str = "fortiweb") -> dict[str, str]:
    return get_json(_naming_key(product), {})


def save_naming(scheme: dict[str, str], product: str = "fortiweb") -> None:
    # Store only non-empty overrides; empties revert to the default pattern via
    # naming.effective_scheme(), exactly like the desktop's "clear → default".
    clean = {k: v.strip() for k, v in (scheme or {}).items() if isinstance(v, str) and v.strip()}
    set_json(_naming_key(product), clean)


def reset_naming(product: str = "fortiweb") -> None:
    set_json(_naming_key(product), {})


# ---- Classification (zones / lines / departments) -------------------------
def classification(kind: str) -> list[str]:
    if kind not in CLASSIFICATION_KINDS:
        return []
    return [str(x).strip() for x in get_json(K_CLS_PREFIX + kind, []) if str(x).strip()]


def all_classification() -> dict[str, list[str]]:
    return {k: classification(k) for k in CLASSIFICATION_KINDS}


def save_classification(kind: str, values: list[str]) -> None:
    if kind not in CLASSIFICATION_KINDS:
        return
    seen: list[str] = []
    for v in values:
        v = (v or "").strip()
        if v and v.lower() not in {s.lower() for s in seen}:
            seen.append(v)
    set_json(K_CLS_PREFIX + kind, seen)


# ---- Network segments -----------------------------------------------------
def segments() -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for row in get_json(K_SEGMENTS, []):
        if isinstance(row, dict):
            out.append({f: str(row.get(f, "") or "") for f in SEGMENT_FIELDS})
    return out


def save_segments(rows: list[dict[str, str]]) -> None:
    clean: list[dict[str, str]] = []
    for row in rows:
        name = (row.get("name") or "").strip()
        cidr = (row.get("cidr") or "").strip()
        if not name and not cidr:
            continue  # skip wholly-blank rows
        clean.append({f: (row.get(f, "") or "").strip() for f in SEGMENT_FIELDS})
    set_json(K_SEGMENTS, clean)


# ---- Access control (IP whitelist + allowed users) ------------------------
def ip_whitelist() -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for row in get_json(K_IP_WHITELIST, []):
        if isinstance(row, dict) and (row.get("ip") or "").strip():
            out.append({"ip": str(row.get("ip", "")).strip(),
                        "note": str(row.get("note", "") or "").strip()})
    return out


def save_ip_whitelist(rows: list[dict[str, str]]) -> None:
    clean: list[dict[str, str]] = []
    seen: set[str] = set()
    for row in rows:
        ip = (row.get("ip") or "").strip()
        if not ip or ip in seen:
            continue
        seen.add(ip)
        clean.append({"ip": ip, "note": (row.get("note", "") or "").strip()})
    set_json(K_IP_WHITELIST, clean)


def allowed_users() -> list[str]:
    return [str(u).strip() for u in get_json(K_ALLOWED_USERS, []) if str(u).strip()]


def save_allowed_users(usernames: list[str]) -> None:
    seen: list[str] = []
    for u in usernames:
        u = (u or "").strip()
        if u and u not in seen:
            seen.append(u)
    set_json(K_ALLOWED_USERS, seen)


# ---- Branding / Banner templates -----------------------------------------
K_BANNER_PREFIX = "branding.banner."   # + fortiweb|fortiadc -> template id

BANNER_TEMPLATES = {
    # --- Solids ---
    "slate":    {"name": "Slate (default)", "bg": "#162940"},
    "midnight": {"name": "Midnight",        "bg": "#0c1422"},
    "onyx":     {"name": "Onyx",            "bg": "#111317"},
    "forest":   {"name": "Forest",          "bg": "#10241b"},
    "navy":     {"name": "Deep Navy",       "bg": "#0a1a3a"},
    "plum":     {"name": "Plum",            "bg": "#241430"},
    # --- Gradients ---
    "ocean":    {"name": "Ocean Blue",      "bg": "linear-gradient(135deg, #0e2a47 0%, #1d63b0 100%)"},
    "ember":    {"name": "Ember Red",       "bg": "linear-gradient(135deg, #2a0e0e 0%, #c0392b 100%)"},
    "graphite": {"name": "Graphite",        "bg": "linear-gradient(135deg, #1b1b1f 0%, #34353b 100%)"},
    "emerald":  {"name": "Emerald",         "bg": "linear-gradient(135deg, #06281f 0%, #10b981 100%)"},
    "violet":   {"name": "Violet",          "bg": "linear-gradient(135deg, #1e1033 0%, #7c3aed 100%)"},
    "sunset":   {"name": "Sunset",          "bg": "linear-gradient(135deg, #3a1020 0%, #f97316 100%)"},
    "teal":     {"name": "Teal",            "bg": "linear-gradient(135deg, #06262b 0%, #0d9488 100%)"},
    "indigo":   {"name": "Indigo",          "bg": "linear-gradient(135deg, #0d1238 0%, #4f46e5 100%)"},
    "amber":    {"name": "Amber Gold",      "bg": "linear-gradient(135deg, #2b1d05 0%, #d97706 100%)"},
    "rose":     {"name": "Rose",            "bg": "linear-gradient(135deg, #2c0d1c 0%, #e11d48 100%)"},
    "steel":    {"name": "Steel",           "bg": "linear-gradient(135deg, #1a2230 0%, #475569 100%)"},
    "aurora":   {"name": "Aurora",          "bg": "linear-gradient(135deg, #0b2545 0%, #1d63b0 45%, #10b981 100%)"},
    "fortinet": {"name": "Fortinet",        "bg": "linear-gradient(135deg, #14233a 0%, #ee3124 100%)"},
}
# ADOMs that carry a personal top-bar banner. Derived LIVE from the ADOM
# registry (``cap_banner``) — adding/removing a banner ADOM is now a Settings →
# ADOMs edit, not a code change. Kept as a module name so ``store.BANNER_PRODUCTS``
# (settings view, auth/routes, user_settings_store) keeps working; the object is
# a live sequence that re-reads the registry on every access.
from ..branding import live_products as _live_products  # noqa: E402

BANNER_PRODUCTS = _live_products("banner")


def banner_template(product: str) -> str:
    val = get_str(K_BANNER_PREFIX + product)
    if val in BANNER_TEMPLATES:
        return val
    # Per-ADOM default now lives on the registry row (``banner_default``).
    try:
        from ..branding import get_product
        default = get_product(product).get("banner_default")
        if default in BANNER_TEMPLATES:
            return default
    except Exception:
        pass
    return "slate"


def banner_bg(product: str) -> str:
    return BANNER_TEMPLATES[banner_template(product)]["bg"]


# ---- Certificate Manager --------------------------------------------------
# Everything the admin fills in Settings → Certificate Manager. NOTHING is
# hardcoded: the signing command itself is a placeholder TEMPLATE the admin
# writes, so a change to the ADCS command/attribs is a form edit, not a code
# change. The domain secret is Fernet-encrypted (never plaintext, never git).
K_CERTMGR_ADCS = "certmgr.adcs"          # JSON connection + globals
K_CERTMGR_CLASS = "certmgr.class."       # + server|clientserver|client -> JSON

CERT_CLASSES = ("server", "clientserver", "client")
CERT_CLASS_LABELS = {
    "server": "Server (Server Authentication)",
    "clientserver": "Client+Server (both EKU)",
    "client": "Client (Client Authentication)",
}

# Placeholders the admin may use in the signing / revoke command templates.
CERT_CMD_TOKENS = (
    "{bin}", "{user}", "{domain}", "{password}", "{ca}", "{ca_name}",
    "{template}", "{csr}", "{out}", "{serial}", "{request_id}",
)

# Sensible, EDITABLE defaults. The submit_cmd mirrors the operator's
# `certreq -submit -attrib "CertificateTemplate:xxx" -config <ca> csr cert`
# but expressed for the Linux ADCS client (certipy) that runs on this box.
_CERT_CLASS_DEFAULTS = {
    "template": "",
    "key_type": "rsa",
    "key_size": "2048",
    "subject_format": "CN={cn}",
    "san_format": "DNS:{cn}",
    "submit_cmd": ('certipy req -u {user}@{domain} -p {password} -dc-ip {ca} '
                   '-ca {ca_name} -template {template} -csr {csr} -out {out}'),
    "revoke_cmd": ('certipy ca -u {user}@{domain} -p {password} -dc-ip {ca} '
                   '-ca {ca_name} -revoke -serial {serial}'),
    "renew_before_days": "30",
}
_CERT_CLASS_FIELDS = tuple(_CERT_CLASS_DEFAULTS.keys())

_CERTMGR_ADCS_DEFAULTS = {
    "bin": "certipy",
    "ca": "",           # {ca} — DC/CA host or config string ("pkiserver")
    "ca_name": "",      # {ca_name} — the CA name
    "domain": "",       # {domain}
    "user": "",         # {user} — enrolment account
    "date_format": "%Y%m%d",
    "notify_to": "",    # comma/newline recipients for lifecycle emails
}


def _certmgr_encrypt(secret: str) -> str:
    if not secret:
        return ""
    try:
        from .encryption import encrypt
        return encrypt(secret)
    except Exception:  # noqa: BLE001 — never block save on a crypto glitch
        return ""


def _certmgr_decrypt(token: str) -> str:
    if not token:
        return ""
    try:
        from .encryption import decrypt
        return decrypt(token)
    except Exception:  # noqa: BLE001
        return ""


def cert_manager_adcs(*, reveal_secret: bool = False) -> dict[str, Any]:
    """The ADCS connection + Certificate-Manager globals.

    ``reveal_secret=True`` decrypts the domain password (the signing cycle needs
    it); the UI never reveals it (a filled field just means "unchanged")."""
    raw = get_json(K_CERTMGR_ADCS, {})
    cfg = dict(_CERTMGR_ADCS_DEFAULTS)
    if isinstance(raw, dict):
        for k in _CERTMGR_ADCS_DEFAULTS:
            if raw.get(k) is not None:
                cfg[k] = str(raw.get(k))
    cfg["has_secret"] = bool(raw.get("secret_enc")) if isinstance(raw, dict) else False
    cfg["secret"] = _certmgr_decrypt(raw.get("secret_enc", "")) if reveal_secret and isinstance(raw, dict) else ""
    return cfg


def save_cert_manager_adcs(values: dict[str, Any]) -> None:
    """Persist the ADCS globals. A blank ``secret`` LEAVES the stored one intact
    (so re-saving the form doesn't wipe the password)."""
    raw = get_json(K_CERTMGR_ADCS, {})
    raw = raw if isinstance(raw, dict) else {}
    out = dict(raw)
    for k in _CERTMGR_ADCS_DEFAULTS:
        if k in values:
            out[k] = str(values.get(k) or "").strip()
    out["bin"] = out.get("bin", "").strip() or "certipy"
    out["date_format"] = out.get("date_format", "").strip() or "%Y%m%d"
    secret = values.get("secret")
    if secret is not None and str(secret).strip():
        out["secret_enc"] = _certmgr_encrypt(str(secret).strip())
    if values.get("clear_secret"):
        out["secret_enc"] = ""
    set_json(K_CERTMGR_ADCS, out)


def cert_class_config(cls: str) -> dict[str, str]:
    """The per-class parameters (template / key / subject+san format / commands /
    renew window). Unknown class → the server defaults."""
    cls = cls if cls in CERT_CLASSES else "server"
    raw = get_json(K_CERTMGR_CLASS + cls, {})
    cfg = dict(_CERT_CLASS_DEFAULTS)
    if isinstance(raw, dict):
        for k in _CERT_CLASS_FIELDS:
            if raw.get(k) is not None and str(raw.get(k)).strip():
                cfg[k] = str(raw.get(k)).strip()
    return cfg


def save_cert_class_config(cls: str, values: dict[str, str]) -> None:
    if cls not in CERT_CLASSES:
        return
    out = {k: str(values.get(k, "") or "").strip() for k in _CERT_CLASS_FIELDS}
    set_json(K_CERTMGR_CLASS + cls, out)


def all_cert_class_configs() -> dict[str, dict[str, str]]:
    return {c: cert_class_config(c) for c in CERT_CLASSES}


# ---- Certificate Manager: issuance protocol (pluggable CA backend) ---------
# The signing/revocation BACKEND is selectable in the admin console. "adcs"
# is the classic command-template path (certipy/certreq against a Microsoft
# CA); "acme" drives an ACME client (certbot/acme.sh/lego) through the same
# command-template contract, so switching protocol is a Settings change —
# never a code change. New protocols = a new entry here + a template set.
K_CERTMGR_PROTOCOL = "certmgr.protocol"
K_CERTMGR_ACME = "certmgr.acme"

CERT_PROTOCOLS = ("adcs", "acme")
CERT_PROTOCOL_LABELS = {
    "adcs": "ADCS / enterprise CA (command template — certipy, certreq…)",
    "acme": "ACME (RFC 8555 — certbot, acme.sh, lego…)",
}

# Placeholders usable in the ACME submit/revoke command templates.
ACME_CMD_TOKENS = (
    "{bin}", "{directory}", "{email}", "{eab_kid}", "{eab_hmac}",
    "{challenge}", "{csr}", "{out}", "{cert}", "{serial}",
)

_CERTMGR_ACME_DEFAULTS = {
    "bin": "certbot",
    "directory_url": "",      # {directory} — ACME directory (empty = client default)
    "account_email": "",      # {email}
    "eab_kid": "",            # {eab_kid} — External Account Binding key id
    "challenge": "http-01",   # {challenge} — http-01 | dns-01
    "submit_cmd": ("{bin} certonly --non-interactive --agree-tos -m {email} "
                   "--server {directory} --preferred-challenges {challenge} "
                   "--csr {csr} --cert-path {out} --standalone"),
    "revoke_cmd": ("{bin} revoke --non-interactive --server {directory} "
                   "--cert-path {cert} --reason superseded"),
}


def cert_manager_protocol() -> str:
    p = get_str(K_CERTMGR_PROTOCOL)
    return p if p in CERT_PROTOCOLS else "adcs"


def save_cert_manager_protocol(protocol: str) -> None:
    if protocol in CERT_PROTOCOLS:
        set_str(K_CERTMGR_PROTOCOL, protocol)


def cert_manager_acme(*, reveal_secret: bool = False) -> dict[str, Any]:
    """The ACME client config. The EAB HMAC key is stored encrypted; the UI
    never reveals it (``has_secret`` just means "one is stored")."""
    raw = get_json(K_CERTMGR_ACME, {})
    cfg = dict(_CERTMGR_ACME_DEFAULTS)
    if isinstance(raw, dict):
        for k in _CERTMGR_ACME_DEFAULTS:
            if raw.get(k) is not None and str(raw.get(k)).strip():
                cfg[k] = str(raw.get(k)).strip()
    cfg["has_secret"] = bool(raw.get("eab_hmac_enc")) if isinstance(raw, dict) else False
    cfg["eab_hmac"] = (_certmgr_decrypt(raw.get("eab_hmac_enc", ""))
                       if reveal_secret and isinstance(raw, dict) else "")
    return cfg


def save_cert_manager_acme(values: dict[str, Any]) -> None:
    """Persist the ACME config. A blank ``eab_hmac`` leaves the stored one."""
    raw = get_json(K_CERTMGR_ACME, {})
    out = dict(raw) if isinstance(raw, dict) else {}
    for k in _CERTMGR_ACME_DEFAULTS:
        if k in values:
            out[k] = str(values.get(k) or "").strip()
    out["bin"] = out.get("bin", "").strip() or "certbot"
    if out.get("challenge") not in ("http-01", "dns-01"):
        out["challenge"] = "http-01"
    secret = values.get("eab_hmac")
    if secret is not None and str(secret).strip():
        out["eab_hmac_enc"] = _certmgr_encrypt(str(secret).strip())
    if values.get("clear_eab_hmac"):
        out["eab_hmac_enc"] = ""
    set_json(K_CERTMGR_ACME, out)


# ---- Certificate Manager: lifecycle policy (revocation + device cleanup) ---
# WHEN a superseded certificate gets revoked at the CA, and WHEN old material
# gets DELETED off the FortiWebs — the retention contract of the whole fleet.
# The sweep itself lives in services.cert_manager.run_lifecycle_sweep and the
# ``cert_lifecycle`` scheduled action; it only consumes these values.
K_CERTMGR_LIFECYCLE = "certmgr.lifecycle"

_CERTMGR_LIFECYCLE_DEFAULTS = {
    "revoke_on_supersede": True,        # revoke the OLD cert after a swap…
    "revoke_grace_days": 7,             # …once it has been superseded N days
    "delete_superseded_after_days": 14, # remove superseded+unbound certs from the box after N days
    "delete_expired_after_days": 30,    # remove expired+unbound certs after N days past expiry
    "delete_revoked_from_device": True, # revoked+unbound certs never stay on a box
    "auto_apply": False,                # scheduled sweep applies (True) or reports-only (False)
}


def cert_lifecycle_policy() -> dict[str, Any]:
    raw = get_json(K_CERTMGR_LIFECYCLE, {})
    cfg = dict(_CERTMGR_LIFECYCLE_DEFAULTS)
    if isinstance(raw, dict):
        for k, dv in _CERTMGR_LIFECYCLE_DEFAULTS.items():
            if k not in raw:
                continue
            if isinstance(dv, bool):
                cfg[k] = bool(raw[k])
            else:
                try:
                    cfg[k] = max(0, int(raw[k]))
                except (TypeError, ValueError):
                    pass
    return cfg


def save_cert_lifecycle_policy(values: dict[str, Any]) -> None:
    out = {}
    for k, dv in _CERTMGR_LIFECYCLE_DEFAULTS.items():
        v = values.get(k, dv)
        if isinstance(dv, bool):
            out[k] = bool(v)
        else:
            try:
                out[k] = max(0, int(v))
            except (TypeError, ValueError):
                out[k] = dv
    set_json(K_CERTMGR_LIFECYCLE, out)


def cert_manager_configured() -> bool:
    """True once the ACTIVE protocol's backend is usable: ADCS needs the CA
    host + name + enrolment user and at least one class template; ACME needs
    a directory URL (or a fully custom submit command)."""
    if cert_manager_protocol() == "acme":
        a = cert_manager_acme()
        return bool(a.get("directory_url") or
                    a.get("submit_cmd") != _CERTMGR_ACME_DEFAULTS["submit_cmd"])
    a = cert_manager_adcs()
    if not (a.get("ca") and a.get("ca_name") and a.get("user")):
        return False
    return any(cert_class_config(c).get("template") for c in CERT_CLASSES)


def all_banners() -> dict:
    return {p: banner_template(p) for p in BANNER_PRODUCTS}


def save_banners(mapping: dict) -> None:
    for product, tpl in (mapping or {}).items():
        if product in BANNER_PRODUCTS and tpl in BANNER_TEMPLATES:
            set_str(K_BANNER_PREFIX + product, tpl)


# ---------------------------------------------------------------------------
#  SoT & Backup server (Settings → admin console → "SoT & Backup" tab)
#
#  Two pieces of the fleet source-of-truth architecture that live OUTSIDE the
#  code repo:
#   * the firmware SoT repository — a SEPARATE git repo (manifest only; the
#     .out binaries live on the backup server, git is the wrong tool for them)
#   * the external backup server (backup-server) — the SFTP box the Fortinet
#     appliances push their own scheduled config backups to, and where the
#     firmware binaries are stored. OFortMAut reads it to list/pull.
#  The SFTP password is Fernet-encrypted at rest, same pattern as the
#  Certificate Manager domain secret.
# ---------------------------------------------------------------------------
K_FW_REPO_URL = "sot.firmware_repo_url"
K_FW_REPO_BRANCH = "sot.firmware_repo_branch"
K_BACKUPSRV = "backup_server.config"                # JSON dict, password_enc inside

_BACKUPSRV_DEFAULTS = {
    "host": "", "port": 22, "protocol": "sftp", "username": "",
    "password_enc": "", "config_path": "/configs", "firmware_path": "/firmware",
}


def firmware_repo() -> dict:
    return {
        "url": get_str(K_FW_REPO_URL, "") or "",
        "branch": get_str(K_FW_REPO_BRANCH, "main") or "main",
    }


def save_firmware_repo(url: str, branch: str) -> None:
    set_str(K_FW_REPO_URL, (url or "").strip())
    set_str(K_FW_REPO_BRANCH, (branch or "main").strip() or "main")


def backup_server(reveal_secret: bool = False) -> dict:
    raw = get_json(K_BACKUPSRV, {}) or {}
    cfg = dict(_BACKUPSRV_DEFAULTS)
    if isinstance(raw, dict):
        cfg.update({k: raw.get(k, v) for k, v in _BACKUPSRV_DEFAULTS.items()})
    try:
        cfg["port"] = int(cfg.get("port") or 22)
    except (TypeError, ValueError):
        cfg["port"] = 22
    cfg["password"] = _certmgr_decrypt(cfg.get("password_enc", "")) if reveal_secret else ""
    cfg["configured"] = bool(cfg.get("host") and cfg.get("username"))
    return cfg


def save_backup_server(form: dict) -> None:
    cur = get_json(K_BACKUPSRV, {}) or {}
    out = {
        "host": (form.get("host") or "").strip(),
        "port": form.get("port") or 22,
        "protocol": "sftp",
        "username": (form.get("username") or "").strip(),
        "password_enc": cur.get("password_enc", ""),
        "config_path": (form.get("config_path") or "/configs").strip() or "/configs",
        "firmware_path": (form.get("firmware_path") or "/firmware").strip() or "/firmware",
    }
    try:
        out["port"] = max(1, min(65535, int(out["port"])))
    except (TypeError, ValueError):
        out["port"] = 22
    pwd = (form.get("password") or "").strip()
    if pwd:  # blank = keep current, same convention as the git token field
        out["password_enc"] = _certmgr_encrypt(pwd)
    set_json(K_BACKUPSRV, out)
