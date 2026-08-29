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
K_ALLOWED_USERS_LEGACY = "access.allowed_users"     # REMOVED gate; see below
K_TIMEZONE = "general.timezone"                     # IANA tz name, e.g. Europe/Zurich
K_LOG_FORMAT = "general.log_format"                 # plain | detailed | json
K_ENV_MODE = "general.env_mode"                     # production | development

LOG_LEVELS_ALL = ["DEBUG", "INFO", "WARNING", "ERROR"]
ENV_MODES = ("production", "development")
LOG_FORMATS = ["plain", "detailed", "json"]
DEFAULT_TIMEZONE = "Europe/Zurich"
CLASSIFICATION_KINDS = ("zones", "lines", "departments")
#: Scalar segment columns. ``department`` is NOT here any more -- see
#: :data:`SEGMENT_LIST_FIELDS`.
SEGMENT_STR_FIELDS = ("name", "zone", "line", "cidr", "interface", "gateway", "note")
#: Columns whose value is a LIST. A network serves whatever departments use
#: it, and ``cidr``/``interface``/``gateway`` are properties of the NETWORK,
#: not of a department -- so two departments sharing a network share ONE row.
#: The previous shape (one row per department) duplicated those three fields
#: with nothing keeping the copies equal, and gave two rows the same name,
#: which is what made the three name-resolvers disagree about which row wins.
SEGMENT_LIST_FIELDS = ("departments",)
SEGMENT_FIELDS = SEGMENT_STR_FIELDS + SEGMENT_LIST_FIELDS

DEFAULTS = {
    K_APP_NAME: "SATOM",
    K_DEFAULT_KIND: "fortiweb",
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


#: Returned by :func:`get_json_checked` when the row EXISTS but cannot be
#: turned into the expected value. It is deliberately not ``[]``/``{}``/``None``
#: so a caller cannot use it by accident: any comparison against a real value
#: is False and any truthiness test on it is True.
class _Malformed:
    __slots__ = ()

    def __repr__(self) -> str:      # pragma: no cover - debugging aid
        return "<MALFORMED setting>"


MALFORMED = _Malformed()


def get_json_checked(key: str, default: Any, want: type | tuple = ()) -> Any:
    """:func:`get_json` that does NOT hide a broken row behind the default.

    ``get_json`` answers "unset", "empty" and "unparseable" with the same
    value. For a *preference* that is fine. For anything a security decision
    reads it is not: a half-written or hand-edited row then looks exactly like
    an operator who never configured the feature.

    Returns ``default`` for an absent/blank row, :data:`MALFORMED` when the row
    is present but is not valid JSON (or, when *want* is given, decodes to the
    wrong type), and the decoded value otherwise.
    """
    raw = AppSetting.get(key)
    if raw is None or not str(raw).strip():
        return default
    try:
        val = json.loads(raw)
    except (ValueError, TypeError):
        return MALFORMED
    if want and not isinstance(val, want):
        return MALFORMED
    return val


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
        "default_kind": normalise_default_kind(get_str(K_DEFAULT_KIND)),
        "session_timeout": _to_int(get_str(K_SESSION_TIMEOUT), 60),
        "poll_interval": _to_int(get_str(K_POLL_INTERVAL), 30),
        "show_raw_config": get_str(K_SHOW_RAW) == "1",
        "log_levels": [lv for lv in get_json(K_LOG_LEVELS, LOG_LEVELS_ALL) if lv in LOG_LEVELS_ALL],
        "timezone": _valid_tz(get_str(K_TIMEZONE)),
        "log_format": (get_str(K_LOG_FORMAT) or "plain") if (get_str(K_LOG_FORMAT) or "plain") in LOG_FORMATS else "plain",
        "env_mode": env_mode(),
    }


def to_local(value: Any, fmt: str = "%Y-%m-%d %H:%M %Z") -> str:
    """Format a datetime (or ISO-8601 string) in the admin-configured timezone
    (``general.timezone`` in ``app_settings`` — the single, DB-backed source of
    truth, replicated to every HA node). Naive inputs are treated as UTC. Any
    failure degrades to the raw value instead of raising. This is the ONE
    conversion code path shared by the ``localtime`` Jinja filter and every
    server-side formatter (git_service, monitoring), so the whole UI localizes
    through a single function reading a single timezone source."""
    if not value:
        return "—"
    try:
        from datetime import datetime, timezone as _utc
        from zoneinfo import ZoneInfo
        dt = datetime.fromisoformat(value) if isinstance(value, str) else value
        tzname = general().get("timezone") or "UTC"
        aware = dt.replace(tzinfo=_utc.utc) if dt.tzinfo is None else dt
        return aware.astimezone(ZoneInfo(tzname)).strftime(fmt)
    except Exception:
        try:
            return value.strftime(fmt) if hasattr(value, "strftime") else str(value)
        except Exception:
            return str(value)


def tz_name() -> str:
    """The admin-configured IANA timezone name (validated, never blank).

    Exposed so a template can TELL the operator which clock a form field is in.
    A ``datetime-local`` input carries no zone, so an unlabelled field is a
    guess the operator makes and the server silently overrules."""
    return _valid_tz(get_str(K_TIMEZONE))


def parse_local(value: Any) -> Any:
    """The INVERSE of :func:`to_local`: an HTML ``datetime-local`` value (or any
    naive ISO-8601 string) is read **in the configured timezone** and returned
    as a naive **UTC** datetime for storage. Returns ``None`` for blank/invalid.

    This exists because the two halves were asymmetric: every timestamp was
    DISPLAYED through :func:`to_local` while every form value was STORED as if
    the operator had typed UTC. Typing ``22:00`` in a Europe/Zurich console
    booked a maintenance window that opened at 22:00 UTC — midnight local, two
    hours after the customer was told the outage would start. Nothing failed;
    the change simply ran at the wrong time.

    A value that already carries an offset is honoured as given and merely
    converted — that is an explicit statement about the instant, and rewriting
    it into the console's zone would be overruling the caller.
    """
    if value is None:
        return None
    try:
        from datetime import datetime, timezone as _utc
        from zoneinfo import ZoneInfo
        dt = (datetime.fromisoformat(str(value).strip())
              if not hasattr(value, "year") else value)
    except (ValueError, TypeError):
        return None
    if dt is None:
        return None
    try:
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=ZoneInfo(tz_name()))
        return dt.astimezone(_utc.utc).replace(tzinfo=None)
    except Exception:  # noqa: BLE001 — an unusable tz db must not lose the value
        return dt.replace(tzinfo=None) if dt.tzinfo is not None else dt


#: Los valores que este ajuste guardaba antes de tener un roster. Eran
#: TitleCase y ademas de un vocabulario distinto del de ``Appliance.kind``
#: (minusculas), asi que el ajuste no podia casar con el formulario que decia
#: rellenar. ``FortiWeb-Cloud`` no es una familia de appliance: SATOM no tiene
#: cliente para ella (app/models.py no la enruta), de modo que se pliega a
#: fortiweb en vez de conservarse como una opcion que no lleva a ninguna parte.
_LEGACY_DEFAULT_KIND = {
    "fortiweb": "fortiweb",
    "fortiweb-cloud": "fortiweb",
    "fortiadc": "fortiadc",
    "fortianalyzer": "fortianalyzer",
    "fortiauthenticator": "fortiauthenticator",
}


def platform_choices() -> tuple[tuple[str, str], ...]:
    """El roster de plataformas, del registro de ADOMs. Un solo autor."""
    from .product_scope import device_products
    return device_products()


def normalise_default_kind(value: Any) -> str:
    """La clave de plataforma valida mas cercana a ``value``.

    La plantilla es una pista; esto es la regla. Sin ella un ``default_kind``
    posteado a mano se guardaba tal cual o se plegaba en silencio a FortiWeb,
    que es como elegir FortiAuthenticator acababa siendo FortiWeb sin decirlo.
    """
    try:
        valid = {key for key, _ in platform_choices()}
    except Exception:  # noqa: BLE001 -- un registro roto no puede perder el valor
        valid = set(_LEGACY_DEFAULT_KIND.values())
    raw = str(value or "").strip().lower()
    candidate = _LEGACY_DEFAULT_KIND.get(raw, raw)
    if candidate in valid:
        return candidate
    return "fortiweb" if "fortiweb" in valid else (sorted(valid)[0] if valid else "fortiweb")


def save_general(app_name: str, default_kind: str, session_timeout: Any,
                 poll_interval: Any, show_raw_config: bool,
                 log_levels: list[str], timezone: str = "",
                 log_format: str = "plain", env_mode: str = "") -> None:
    set_str(K_APP_NAME, (app_name or "SATOM").strip())
    set_str(K_DEFAULT_KIND, normalise_default_kind(default_kind))
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
class SegmentError(ValueError):
    """A segment list that must not become durable.

    Raised by :func:`save_segments`. Callers turn it into a flash; nothing is
    written, so a rejected save leaves the previous list exactly as it was.
    """


def normalize_departments(value) -> list[str]:
    """The ONE reader of a segment's departments, whatever shape it arrives in.

    Three shapes reach this function and all three are legitimate:

    * ``list`` -- the current storage shape.
    * ``str``  -- the form field (comma separated) and the LEGACY single
      ``department`` column of every blob written before this change.
    * anything else -- treated as "none named", never as an error, because a
      garbled row must not make the segments page unopenable.

    Case-insensitive de-duplication, first spelling kept: ``["WSG", "wsg"]``
    is one department typed twice, and keeping both would put the same name in
    a badge row twice and count it twice in ``classification_ops.usage``.
    """
    if isinstance(value, str):
        parts = value.split(",")
    elif isinstance(value, (list, tuple)):
        parts = [str(v) for v in value]
    else:
        return []
    out: list[str] = []
    seen: set[str] = set()
    for part in parts:
        val = str(part or "").strip()
        if not val or val.lower() in seen:
            continue
        seen.add(val.lower())
        out.append(val)
    return out


def segments() -> list[dict]:
    """Live segments, always in the CURRENT shape.

    Rows written before departments became a list are read through
    :func:`normalize_departments`, so a blob nobody has re-saved yet still
    answers ``departments`` -- one reader, no migration flag, and no consumer
    that has to know which era its data came from.
    """
    out: list[dict] = []
    for row in get_json(K_SEGMENTS, []):
        if not isinstance(row, dict):
            continue
        seg: dict = {f: str(row.get(f, "") or "") for f in SEGMENT_STR_FIELDS}
        raw = row.get("departments")
        if raw is None:
            raw = row.get("department")          # legacy single-value column
        seg["departments"] = normalize_departments(raw)
        out.append(seg)
    return out


def duplicate_segment_names(rows: list[dict] | None = None) -> list[str]:
    """Names carried by more than one row, in first-seen order.

    Exists so a consumer can REFUSE rather than pick. :func:`save_segments`
    makes new duplicates impossible, but a blob written before that guard --
    or by hand -- can still hold them, and the failure they cause is silent:
    each resolver picks a different row and nothing disagrees out loud.
    """
    rows = segments() if rows is None else rows
    seen: set[str] = set()
    dupes: list[str] = []
    for row in rows:
        name = (row.get("name") or "").strip()
        if not name:
            continue
        if name in seen and name not in dupes:
            dupes.append(name)
        seen.add(name)
    return dupes


def save_segments(rows: list[dict]) -> None:
    """Validate, normalise and store. Raises :class:`SegmentError` on refusal.

    **Names must be unique.** Two rows with the same name are the defect this
    guard exists for: ``line_profiles`` keys segments by name, so a duplicate
    means every resolver silently picks one row and they do not all pick the
    same one. Merging the pair here would be this function deciding which
    CIDR/gateway survives -- so it refuses and says which name to fix.

    Comparison is EXACT, not case-folded: ``DMZ`` and ``dmz`` resolve
    deterministically and identically in every consumer (they key on the exact
    string), so rejecting that pair would invent a rule the system does not
    need -- and would lock an install that already has one out of its own
    segments page.
    """
    clean: list[dict] = []
    seen: dict[str, int] = {}
    dupes: list[str] = []
    for row in rows:
        name = (row.get("name") or "").strip()
        cidr = (row.get("cidr") or "").strip()
        if not name and not cidr:
            continue  # skip wholly-blank rows
        seg: dict = {f: (str(row.get(f, "") or "")).strip()
                     for f in SEGMENT_STR_FIELDS}
        seg["departments"] = normalize_departments(
            row.get("departments", row.get("department")))
        if name:
            if name in seen and name not in dupes:
                dupes.append(name)
            seen[name] = seen.get(name, 0) + 1
        clean.append(seg)
    if dupes:
        raise SegmentError(
            "two or more segments share the name(s) " +
            ", ".join(repr(d) for d in dupes) +
            " — a segment name identifies one network, so add the extra "
            "department to the existing row instead of adding a second row.")
    set_json(K_SEGMENTS, clean)


# ---- Access control (IP whitelist + allowed users) ------------------------
# These two feed ``app.__init__._access_gate``, which treats an EMPTY list as
# "no restriction configured" — lockout-safe and the shipped default. That
# makes "empty" the most permissive answer in the app, so it must never be
# what a broken row decodes to. ``access_config_error()`` is the separate
# signal the gate uses to refuse service instead of admitting everyone.
def _access_rows(key: str) -> Any:
    """Raw list for an access-control key, or :data:`MALFORMED`."""
    return get_json_checked(key, [], want=list)


def ip_whitelist() -> list[dict[str, str]]:
    rows = _access_rows(K_IP_WHITELIST)
    if rows is MALFORMED:
        return []          # never a partial/garbled list — see access_config_error()
    out: list[dict[str, str]] = []
    for row in rows:
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


def access_config_error() -> str:
    """``""`` when the access-control settings can be read, else a message
    naming the key(s) that cannot.

    The gate calls this BEFORE it looks at the contents. Unset and empty are
    not errors — they are the shipped "no restriction" default and denying on
    them would lock every operator out of every existing install. An
    unparseable row is a different fact and gets a different answer.
    """
    broken = [k for k in (K_IP_WHITELIST,)
              if _access_rows(k) is MALFORMED]
    if not broken:
        return ""
    return ("access-control settings are unreadable: %s — the stored value is "
            "not a JSON list. Fix or clear the row(s) before non-admin access "
            "can be evaluated." % ", ".join(broken))


# ---- REMOVED: per-username allowlist --------------------------------------
# The allowlist was a fourth access gate stacked behind the directory group
# filter, the approval gate and the profile, and it enforced nothing they did
# not — while silently expiring on every import. Nothing reads it as policy any
# more. The two helpers below exist for exactly one reason: an upgraded install
# whose stored list just stopped applying deserves to be told, and to be able to
# clear the dead row instead of finding it in a database dump years later.
def stale_allowed_users() -> list[str]:
    """Leftover usernames from the removed allowlist. NOT a policy read."""
    rows = _access_rows(K_ALLOWED_USERS_LEGACY)
    if rows is MALFORMED:
        return []
    return [str(u).strip() for u in rows if str(u).strip()]


def clear_stale_allowed_users() -> None:
    set_json(K_ALLOWED_USERS_LEGACY, [])


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
    "crimson":  {"name": "Crimson",         "bg": "linear-gradient(135deg, #14233a 0%, #ee3124 100%)"},
}

# Renamed template ids. A stored id MUST keep rendering the same colour:
# dropping a key outright makes ``banner_template`` fall through to "slate",
# so any ADOM (or user) that had chosen it is silently repainted with no
# trace anywhere. "crimson" used to be named after the vendor; the colour is
# unchanged, only our label for it.
BANNER_TEMPLATE_ALIASES = {"fortinet": "crimson"}


def resolve_banner_template(val):
    """Map a stored (possibly renamed) template id to its current id."""
    return BANNER_TEMPLATE_ALIASES.get(val, val)


# ADOMs that carry a personal top-bar banner. Derived LIVE from the ADOM
# registry (``cap_banner``) — adding/removing a banner ADOM is now a Settings →
# ADOMs edit, not a code change. Kept as a module name so ``store.BANNER_PRODUCTS``
# (settings view, auth/routes, user_settings_store) keeps working; the object is
# a live sequence that re-reads the registry on every access.
from ..branding import live_products as _live_products  # noqa: E402

BANNER_PRODUCTS = _live_products("banner")


def banner_template(product: str) -> str:
    val = resolve_banner_template(get_str(K_BANNER_PREFIX + product))
    if val in BANNER_TEMPLATES:
        return val
    # Per-ADOM default now lives on the registry row (``banner_default``).
    try:
        from ..branding import get_product
        default = resolve_banner_template(
            get_product(product).get("banner_default"))
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
    "{bin}", "{helper}", "{directory}", "{email}", "{eab_kid}", "{eab_hmac}",
    "{challenge}", "{key_type}", "{acme_path}", "{dns_flag}", "{dns_resolvers}",
    "{dns_propagation_wait}", "{webroot}", "{http_port}",
    "{csr}", "{out}", "{cert}", "{cn}", "{serial}",
)

ACME_CHALLENGES = ("http-01", "dns-01", "tls-alpn-01")
ACME_CLIENTS = ("lego", "custom")
ACME_KEY_TYPES = ("EC256", "EC384", "RSA2048", "RSA3072", "RSA4096")
ACME_HTTP_MODES = ("webroot", "standalone")
ACME_TEMPLATE_MODES = ("auto", "custom")

# Default client = lego: ONE static binary, ~150 DNS providers built in, every
# provider configured purely by ENVIRONMENT. That matters for a product third
# parties install on Debian/RHEL/SUSE/Arch — no Python-version matrix, and no
# 8k-line bash script executed as root.
_CERTMGR_ACME_DEFAULTS = {
    "client": "lego",              # lego | custom (custom = operator writes the cmds)
    "bin": "lego",                 # {bin}
    "helper": "/opt/satom/deploy/acme-hooks/satom-lego-run.sh",  # {helper}
    "directory_url": "",           # {directory} — empty = client default
    "account_email": "",           # {email}
    # {acme_path} — the ACCOUNT KEY lives here and MUST persist: a fresh
    # registration per issuance burns the CA's new-account rate limit and
    # loses the ability to revoke what was issued before.
    "account_key_dir": "/opt/satom/data/acme",
    "tos_agreed": "",              # non-empty = operator accepted the CA's ToS
    "key_type": "EC256",           # {key_type}
    "eab_kid": "",                 # {eab_kid} — External Account Binding key id
    "challenge": "http-01",        # http-01 | dns-01 | tls-alpn-01
    # -- http-01 (web authentication) --------------------------------------
    "http_mode": "webroot",        # webroot (nginx keeps :80) | standalone
    "webroot_path": "/var/www/acme",   # {webroot}
    "http_port": "80",             # {http_port}
    # -- dns-01 -------------------------------------------------------------
    "dns_provider": "",            # slug in the acme_dns_providers catalog
    "dns_resolvers": "",           # {dns_resolvers} — e.g. 1.1.1.1:53
    "dns_propagation_wait": "",    # {dns_propagation_wait} — seconds
    "dns_disable_precheck": "",    # non-empty = --dns.disable-cp
    # -- command templates --------------------------------------------------
    # "auto": regenerated from the catalog + the fields above on every save.
    # "custom": the operator owns the raw templates (admin-only, warned in UI).
    "template_mode": "auto",
    "submit_cmd": "",
    "revoke_cmd": "",
}

# Per-provider credentials: certmgr.acme.creds.<slug>. Kept OUT of the main
# ACME blob so switching provider and switching back never loses a credential.
K_CERTMGR_ACME_CREDS = "certmgr.acme.creds."


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
    """Persist the ACME config. A blank ``eab_hmac`` leaves the stored one.

    In ``template_mode == "auto"`` the submit/revoke commands are REGENERATED
    from the catalog here, so the operator configures fields — never a shell
    command. ``"custom"`` keeps whatever was typed."""
    raw = get_json(K_CERTMGR_ACME, {})
    out = dict(raw) if isinstance(raw, dict) else {}
    for k in _CERTMGR_ACME_DEFAULTS:
        if k in values:
            out[k] = str(values.get(k) or "").strip()
    out["bin"] = out.get("bin", "").strip() or "lego"
    if out.get("client") not in ACME_CLIENTS:
        out["client"] = "lego"
    if out.get("challenge") not in ACME_CHALLENGES:
        out["challenge"] = "http-01"
    if out.get("key_type") not in ACME_KEY_TYPES:
        out["key_type"] = "EC256"
    if out.get("http_mode") not in ACME_HTTP_MODES:
        out["http_mode"] = "webroot"
    if out.get("template_mode") not in ACME_TEMPLATE_MODES:
        out["template_mode"] = "auto"
    if not out.get("account_key_dir"):
        out["account_key_dir"] = _CERTMGR_ACME_DEFAULTS["account_key_dir"]
    secret = values.get("eab_hmac")
    if secret is not None and str(secret).strip():
        out["eab_hmac_enc"] = _certmgr_encrypt(str(secret).strip())
    if values.get("clear_eab_hmac"):
        out["eab_hmac_enc"] = ""

    if out["template_mode"] == "auto":
        # Local import: acme_providers imports this module (catalog credentials).
        from . import acme_providers
        sub, rev = acme_providers.build_commands(out)
        out["submit_cmd"], out["revoke_cmd"] = sub, rev
    set_json(K_CERTMGR_ACME, out)


# ---- Certificate Manager: per-DNS-provider credentials ---------------------
# One app_settings row per provider slug. Fields flagged ``secret`` in the
# catalog are Fernet-encrypted under "<ENV>__enc" and NEVER returned to the
# browser; the UI only learns that a value is stored.
def acme_provider_creds(slug: str, fields, *, reveal: bool = False) -> dict[str, Any]:
    slug = (slug or "").strip()
    if not slug:
        return {}
    raw = get_json(K_CERTMGR_ACME_CREDS + slug, {})
    raw = raw if isinstance(raw, dict) else {}
    out: dict[str, Any] = {}
    for f in fields or []:
        env = str((f or {}).get("env") or "")
        if not env:
            continue
        if f.get("secret"):
            enc = raw.get(env + "__enc", "")
            out[env] = _certmgr_decrypt(enc) if (reveal and enc) else ""
            out[env + "__set"] = bool(enc)
        else:
            out[env] = str(raw.get(env, "") or "")
    return out


def save_acme_provider_creds(slug: str, fields, values: dict[str, Any]) -> None:
    """Blank secret = keep the stored one (same contract as every other secret
    in this console). ``clear__<ENV>`` wipes it."""
    slug = (slug or "").strip()
    if not slug:
        return
    key = K_CERTMGR_ACME_CREDS + slug
    raw = get_json(key, {})
    out = dict(raw) if isinstance(raw, dict) else {}
    for f in fields or []:
        env = str((f or {}).get("env") or "")
        if not env:
            continue
        if f.get("secret"):
            v = values.get(env)
            if v is not None and str(v).strip():
                out[env + "__enc"] = _certmgr_encrypt(str(v).strip())
            if values.get("clear__" + env):
                out[env + "__enc"] = ""
        elif env in values:
            out[env] = str(values.get(env) or "").strip()
    set_json(key, out)


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
        if not a.get("submit_cmd"):
            return False
        if a.get("template_mode") == "custom":
            return True
        if not (a.get("directory_url") and a.get("tos_agreed")):
            return False
        if a.get("challenge") == "dns-01":
            return bool(a.get("dns_provider"))
        return bool(a.get("webroot_path") if a.get("http_mode") == "webroot"
                    else a.get("http_port"))
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
#  Source of Truth & Backup — THREE things this product kept calling one
#
#  The console used to carry a single "SoT & Backup" tab, and that tab held a
#  git URL. Two different readers acted on the word "SoT" and meant different
#  objects; the split below is what the operator asked for on 2026-08-29, and
#  it is spelled out here because the names are the whole point:
#
#   * CONFIGURATION SoT — the ONLY thing this product calls a source of
#     truth. Content-addressed snapshots of the appliances' configuration in
#     ``data/sot/objects`` + the ``sot_version`` index. Retention lives here
#     (``sot.retention_versions`` / ``sot.retention_days``); ``sot_store``
#     reads it.
#   * BACKUP SERVER — a DESTINATION, not an authority: the SFTP box the
#     appliances push their own ``config system backup`` to, where the SATOM
#     system bundles are uploaded and where retired firmware is archived.
#     SATOM connects read-mostly (inventory + pull).
#   * The UPDATE REPOSITORY — where this node downloads its own CODE from.
#     That one is git, it is configured on the Software Update Repository
#     pane, and it lives in ``git_service``, not here. It has never held a
#     device configuration.
#
#  Retired 2026-08-29: ``sot.firmware_repo_url`` / ``sot.firmware_repo_branch``.
#  They pointed at a second git repo holding a firmware *manifest*, and every
#  consumer of them was presentational — the value was rendered as a link and
#  nothing ever read the manifest. The authority for firmware is the
#  ``firmware_images`` table plus ``data/firmware/`` (Infrastructure →
#  Firmware), which is indexed, hashed and backed up. A setting that announces
#  a source of truth nobody reads is worse than no setting: the repo it named
#  declared ``firmwares: []`` while two images were loaded. Firmware is NOT a
#  source of truth in this product, and no key here may say it is.
#
#  The SFTP password is Fernet-encrypted at rest, same pattern as the
#  Certificate Manager domain secret.
# ---------------------------------------------------------------------------
K_SOT_KEEP_VERSIONS = "sot.retention_versions"
K_SOT_KEEP_DAYS = "sot.retention_days"
K_BACKUPSRV = "backup_server.config"                # JSON dict, password_enc inside

_BACKUPSRV_DEFAULTS = {
    "host": "", "port": 22, "protocol": "sftp", "username": "",
    "password_enc": "", "config_path": "/configs", "firmware_path": "/firmware",
    "system_path": "/system",
}


def sot_retention() -> dict:
    """Retention for the CONFIGURATION SoT store, as integers.

    ``sot_store`` used to reach for ``settings_store.get`` — a function that
    has never existed on this module. The call raised ``AttributeError`` inside
    a blanket ``except``, so both knobs silently resolved to the hard-coded
    defaults on every harvest: writing them changed nothing, and nothing said
    so. The accessor lives here now, beside the keys it reads.

    A stored 0 or a malformed value means "unset", not "keep nothing": zero
    would make the next prune delete every version of every device, which is
    not a policy anyone types into a box labelled *keep*.
    """
    from .sot_store import DEFAULT_KEEP_VERSIONS, DEFAULT_KEEP_DAYS
    out = {}
    for key, field, dflt in ((K_SOT_KEEP_VERSIONS, "versions", DEFAULT_KEEP_VERSIONS),
                             (K_SOT_KEEP_DAYS, "days", DEFAULT_KEEP_DAYS)):
        try:
            val = int(get_str(key, "") or 0)
        except (TypeError, ValueError):
            val = 0
        out[field] = val if val > 0 else dflt
    out["default_versions"] = DEFAULT_KEEP_VERSIONS
    out["default_days"] = DEFAULT_KEEP_DAYS
    out["configured"] = bool(get_str(K_SOT_KEEP_VERSIONS, "")
                             or get_str(K_SOT_KEEP_DAYS, ""))
    return out


def save_sot_retention(versions, days) -> None:
    """Store the two retention knobs, clamped to something a prune can honour.

    Out-of-range is clamped rather than rejected: this form has two fields and
    no error channel of its own, so a silently dropped value would leave the
    page showing the old number as though it had been saved.
    """
    from .sot_store import DEFAULT_KEEP_VERSIONS, DEFAULT_KEEP_DAYS
    for key, raw, dflt, hi in ((K_SOT_KEEP_VERSIONS, versions, DEFAULT_KEEP_VERSIONS, 10000),
                               (K_SOT_KEEP_DAYS, days, DEFAULT_KEEP_DAYS, 36500)):
        try:
            val = int(str(raw).strip() or 0)
        except (TypeError, ValueError):
            val = 0
        if val <= 0:
            val = dflt
        set_str(key, str(max(1, min(hi, val))))


# ── Configuration SoT refresh cadence ────────────────────────────────────────
#
# How often the SoT refreshes is deliberately NOT a new key in this table.  The
# number already has an author: ``device_sync`` is the scheduled action that
# reads a device and mints a version, so a key here would be a SECOND author of
# one cadence — the page would show one interval while the scheduler fired on
# another, and neither would be wrong about itself.  That is the same shape as
# the firmware "SoT" that was retired on 2026-08-29: an authority nobody read,
# contradicting the one that was actually in force.  So these two functions
# read and write the schedule row itself.
SOT_REFRESH_ACTION = "device_sync"
SOT_REFRESH_DEFAULT_MINUTES = 60
SOT_REFRESH_MIN_MINUTES = 5
SOT_REFRESH_MAX_MINUTES = 10080  # one week

_SOT_REFRESH_UNIT_MINUTES = {"minutes": 1, "hours": 60, "days": 1440}


def _sot_refresh_rows():
    from ..models import ScheduledAction
    return (ScheduledAction.query
            .filter_by(action=SOT_REFRESH_ACTION)
            .order_by(ScheduledAction.id).all())


def _sot_refresh_primary(rows):
    """The row this knob speaks for: the first INTERVAL harvest.

    A harvest pinned to a wall-clock time is a different statement ("every
    night at 02:00") and silently converting it to an interval would discard
    it. Such a row is reported as *other*, not edited.
    """
    for r in rows:
        if (r.schedule_kind or "") == "interval":
            return r
    return None


def sot_refresh() -> dict:
    """Cadence of the harvest that mints Configuration SoT versions."""
    try:
        rows = _sot_refresh_rows()
    except Exception:  # noqa: BLE001 — settings must render without a schedule table
        rows = []
    primary = _sot_refresh_primary(rows)
    minutes = SOT_REFRESH_DEFAULT_MINUTES
    if primary is not None:
        spec = primary.schedule_dict if hasattr(primary, "schedule_dict") else {}
        try:
            every = int((spec or {}).get("every", 0))
        except (TypeError, ValueError):
            every = 0
        unit = _SOT_REFRESH_UNIT_MINUTES.get((spec or {}).get("unit", "minutes"), 1)
        minutes = every * unit if every > 0 else SOT_REFRESH_DEFAULT_MINUTES
    return {
        "minutes": minutes,
        "default_minutes": SOT_REFRESH_DEFAULT_MINUTES,
        "min_minutes": SOT_REFRESH_MIN_MINUTES,
        "max_minutes": SOT_REFRESH_MAX_MINUTES,
        "configured": primary is not None,
        "enabled": bool(getattr(primary, "enabled", False)),
        "action_id": getattr(primary, "id", None),
        "last_run": getattr(primary, "last_run", None),
        "next_run": getattr(primary, "next_run", None),
        "others": max(0, len(rows) - (1 if primary is not None else 0)),
    }


def save_sot_refresh(minutes) -> dict:
    """Write the cadence to the harvest row and RECOMPUTE its next fire.

    Recomputing ``next_run`` is the point of the function. Without it a
    shortened interval does not apply until the fire that was already pending
    goes off, so the page would claim a cadence the node would not honour for
    another hour — the setting would look saved and be inert, which is exactly
    the failure the retention knob had.

    Out of range is clamped, not rejected: this form has one field and no error
    channel, and a silently dropped value leaves the old number on screen as
    though it had been stored.
    """
    from ..models import ScheduledAction
    from ..extensions import db
    from .scheduler import compute_next_run

    try:
        val = int(str(minutes).strip() or 0)
    except (TypeError, ValueError):
        val = 0
    if val <= 0:
        val = SOT_REFRESH_DEFAULT_MINUTES
    val = max(SOT_REFRESH_MIN_MINUTES, min(SOT_REFRESH_MAX_MINUTES, val))

    rows = _sot_refresh_rows()
    row = _sot_refresh_primary(rows)
    created = False
    if row is None:
        created = True
        row = ScheduledAction(
            name="Fleet sync (source of truth)",
            scope="admin", product="fortiweb", action=SOT_REFRESH_ACTION,
            targets="[]", params="{}", enabled=True, catch_up=True,
            created_by="settings.sot_refresh")
        db.session.add(row)
    row.schedule_kind = "interval"
    row.schedule = json.dumps({"every": val, "unit": "minutes"})
    row.next_run = compute_next_run("interval", {"every": val, "unit": "minutes"})
    db.session.commit()
    return {"minutes": val, "created": created, "action_id": row.id}


# ── System bundle schedule ───────────────────────────────────────────────────
#
# Same rule as the SoT cadence above, and for the same reason: the hour a
# bundle is written at ALREADY has an author.  ``system_backup`` is the
# scheduled action that dumps Postgres, packs the JSON tree and the SoT blobs
# and uploads the result, so a settings key here would be a SECOND author of
# one hour — the page would print 01:30 while the node backed up at 03:00, and
# neither would be wrong about itself.
#
# It diverges from the SoT knob in one deliberate way.  ``save_sot_refresh``
# creates a row when it finds no INTERVAL harvest even though a wall-clock one
# exists: two harvests cost device calls.  Two system backups cost a full
# bundle each — 578 MB apiece on a node with 9 GB free — so when the bundle is
# already scheduled some other way this REFUSES and says so, rather than adding
# a second nightly run nobody asked for.
SYSTEM_BACKUP_ACTION = "system_backup"
SYSTEM_BACKUP_DEFAULT_TIME = "01:30"


def _system_backup_rows():
    from ..models import ScheduledAction
    return (ScheduledAction.query
            .filter_by(action=SYSTEM_BACKUP_ACTION)
            .order_by(ScheduledAction.id).all())


def _system_backup_primary(rows):
    """The row this knob speaks for: the first DAILY bundle run."""
    for r in rows:
        if (r.schedule_kind or "") == "daily":
            return r
    return None


def _normalise_hhmm(value, fallback: str) -> str:
    """``HH:MM``, or the hour already in force — never a silent ``00:00``.

    This form has one field and no error channel.  A submit the parser cannot
    read must therefore leave the backup where it is: defaulting to midnight
    would relocate a nightly job to the hour the fleet is least watched and
    make it look like somebody asked for that.
    """
    try:
        parts = str(value or "").strip().split(":")
        h, m = int(parts[0]), int(parts[1])
    except (ValueError, TypeError, IndexError):
        return fallback
    if not (0 <= h <= 23 and 0 <= m <= 59):
        return fallback
    return "%02d:%02d" % (h, m)


def system_backup_schedule() -> dict:
    """When this node writes and uploads its OWN bundle (not a device backup)."""
    try:
        rows = _system_backup_rows()
    except Exception:  # noqa: BLE001 — settings must render without a schedule table
        rows = []
    primary = _system_backup_primary(rows)
    at = SYSTEM_BACKUP_DEFAULT_TIME
    if primary is not None:
        spec = primary.schedule_dict if hasattr(primary, "schedule_dict") else {}
        at = _normalise_hhmm((spec or {}).get("time"), SYSTEM_BACKUP_DEFAULT_TIME)
    return {
        "time": at,
        "default_time": SYSTEM_BACKUP_DEFAULT_TIME,
        # The hour is WALL-CLOCK in this zone, not UTC.  Printing "01:30" with
        # no zone beside it is the ambiguity that had a nightly job running at
        # 03:00 in winter and 04:00 in summer before the scheduler learned
        # about time zones at all.
        "tz": tz_name(),
        "configured": primary is not None,
        "enabled": bool(getattr(primary, "enabled", False)),
        "action_id": getattr(primary, "id", None),
        "last_run": getattr(primary, "last_run", None),
        "last_status": getattr(primary, "last_status", None),
        "next_run": getattr(primary, "next_run", None),
        # A bundle scheduled some other way (weekly, or every N hours) is a
        # different statement and one hour field cannot express it.  Reported,
        # so the pane can send the operator to Automation instead of claiming
        # this node has no bundle schedule at all.
        "other_kind": (rows[0].schedule_kind if rows and primary is None else None),
        "others": max(0, len(rows) - (1 if primary is not None else 0)),
    }


def save_system_backup_schedule(value) -> dict:
    """Write the hour to the bundle row and RECOMPUTE its next fire.

    ``tz`` is passed into the schedule math because ``daily`` is a WALL-CLOCK
    kind: computed in UTC, "01:30" typed on a Europe/Zurich console fires at
    03:30 local in summer.  Omitting it here while the Automation page passes
    it would leave two pages disagreeing about the same row — which is the
    whole failure this knob exists to avoid.
    """
    from ..models import ScheduledAction
    from ..extensions import db
    from .scheduler import compute_next_run

    rows = _system_backup_rows()
    row = _system_backup_primary(rows)
    if row is None and rows:
        return {"conflict": True, "kind": (rows[0].schedule_kind or "custom"),
                "time": None, "created": False, "action_id": rows[0].id}

    current = SYSTEM_BACKUP_DEFAULT_TIME
    if row is not None:
        current = _normalise_hhmm((row.schedule_dict or {}).get("time"),
                                  SYSTEM_BACKUP_DEFAULT_TIME)
    hhmm = _normalise_hhmm(value, current)

    created = False
    if row is None:
        created = True
        row = ScheduledAction(
            name="Nightly system backup (Postgres + JSON -> backup-server)",
            scope="admin", product="fortiweb", action=SYSTEM_BACKUP_ACTION,
            targets="[]", params=json.dumps({"push_server": True}),
            enabled=True, catch_up=True,
            created_by="settings.system_backup_schedule")
        db.session.add(row)
    row.schedule_kind = "daily"
    row.schedule = json.dumps({"time": hhmm})
    row.next_run = compute_next_run("daily", {"time": hhmm}, tz=tz_name())
    db.session.commit()
    return {"conflict": False, "time": hhmm, "created": created,
            "action_id": row.id}


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
        "system_path": (form.get("system_path") or "/system").strip() or "/system",
    }
    try:
        out["port"] = max(1, min(65535, int(out["port"])))
    except (TypeError, ValueError):
        out["port"] = 22
    pwd = (form.get("password") or "").strip()
    if pwd:  # blank = keep current, same convention as the git token field
        out["password_enc"] = _certmgr_encrypt(pwd)
    set_json(K_BACKUPSRV, out)
