"""Theme engine — validation, activation and CSS emission for Settings -> Appearance.

The console's look is a set of ``--fw-*`` custom properties (registry in
``theme_tokens.py``, GENERATED from the stylesheet). A theme stores the subset an
operator changed; this module turns that into a nonced ``<style>`` block on every
page.

Three rules hold this together, and each exists because the alternative has a
concrete failure mode:

1. **Values are allowlisted per token KIND, never passed through.**
   A token value ends up inside a ``<style>`` element. Accepting free text there
   is stored CSS injection with the app's own CSP nonce on it — an attacker-
   controlled ``}`` ends the rule and starts a new one. Every value must match a
   narrow regex for its kind AND survive a shared reject list; anything else is
   refused with the token named.

2. **Only overrides are stored, and emission skips no-ops.**
   A theme that changes the accent emits one line, not twenty-nine. Stylesheet
   improvements keep reaching themes that never opted out of them.

3. **Built-ins are immutable and one is always present.**
   The realistic accident here is an operator picking two dark colours and
   locking themselves out of the very page that would fix it. ``SATOM Classic``
   can never be edited or deleted, ``reset_to_builtin()`` is one call, and the
   operator CLI can run it on a node whose UI is unusable.

The active theme is cached module-side with a short TTL (same pattern as
``branding``) so every gunicorn worker converges after an edit without a restart.
"""
from __future__ import annotations

import re
import time

from .theme_tokens import (DEFAULTS, GROUP_ORDER, TOKENS, TOKEN_NAMES,  # noqa: F401
                           by_group)

__all__ = [
    "validate_tokens", "audit_contrast", "css_for", "active_theme",
    "active_css", "set_active", "seed_defaults", "reset_to_builtin",
    "invalidate", "BUILTIN_SLUG", "contrast_ratio",
]

BUILTIN_SLUG = "satom-classic"

# ── validation ──────────────────────────────────────────────────────────────
# Anything on this list is refused regardless of kind. These are the characters
# and sequences that let a value escape its declaration.
_FORBIDDEN = (";", "{", "}", "<", ">", "\\", "/*", "*/", "url(", "expression(",
              "@import", "javascript:", "\n", "\r")

_MAX_LEN = 240

_HEX = r"#(?:[0-9a-fA-F]{3,4}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})"
_NUM = r"-?\d+(?:\.\d+)?"

VALIDATORS: "dict[str, re.Pattern]" = {
    # #rgb / #rgba / #rrggbb / #rrggbbaa, rgb()/rgba() with numeric args only.
    "color": re.compile(
        r"^(?:%s|rgba?\(\s*%s%%?\s*(?:[, ]\s*%s%%?\s*){2,3}(?:/\s*%s%%?\s*)?\))$"
        % (_HEX, _NUM, _NUM, _NUM)),
    # 0 or a number with an absolute/relative unit.
    "length": re.compile(r"^(?:0|%s(?:px|rem|em|%%|vh|vw|ch))$" % _NUM),
    # One or more shadow layers: offsets/blur/spread plus a colour, optional
    # `inset`. Character-allowlisted so nothing structural can appear.
    "shadow": re.compile(r"^(?:none|[0-9a-zA-Z#.,()%\s-]+)$"),
    # "<time> <easing>" — the only shape the stylesheet uses.
    "transition": re.compile(
        r"^%s(?:s|ms)\s+(?:ease|ease-in|ease-out|ease-in-out|linear"
        r"|step-start|step-end|cubic-bezier\(\s*%s\s*,\s*%s\s*,\s*%s\s*,\s*%s\s*\))$"
        % (_NUM, _NUM, _NUM, _NUM, _NUM)),
    # A font stack: family names (quoted or bare) separated by commas.
    "font": re.compile(r"^[A-Za-z0-9 ,'\"_-]+$"),
}


def _reject_reason(raw: str) -> "str | None":
    if not raw:
        return "empty value"
    if len(raw) > _MAX_LEN:
        return "value longer than %d characters" % _MAX_LEN
    low = raw.lower()
    for bad in _FORBIDDEN:
        if bad in low:
            return "contains %r, which is not allowed in a token value" % bad
    return None


def validate_tokens(raw: "dict[str, str]") -> "tuple[dict[str, str], list[str]]":
    """Return ``(overrides, errors)``.

    ``overrides`` holds only the tokens that are known, valid AND actually differ
    from the stylesheet default — storing a value equal to the default would
    freeze it against future stylesheet changes for no benefit.
    Unknown token names are reported, not silently dropped: a typo that vanishes
    looks exactly like a control that does not work.
    """
    clean: "dict[str, str]" = {}
    errors: "list[str]" = []
    for name, value in (raw or {}).items():
        name = str(name).strip()
        if name not in TOKENS:
            errors.append("%s: unknown design token" % name)
            continue
        val = " ".join(str(value).split())
        why = _reject_reason(val)
        if why:
            errors.append("%s: %s" % (TOKENS[name]["label"], why))
            continue
        kind = TOKENS[name]["kind"]
        pattern = VALIDATORS.get(kind)
        if pattern is None or not pattern.match(val):
            errors.append("%s: %r is not a valid %s value" % (
                TOKENS[name]["label"], val, kind))
            continue
        if val != DEFAULTS[name]:
            clean[name] = val
    return clean, errors


# ── contrast auditing ───────────────────────────────────────────────────────
def _parse_rgb(value: str) -> "tuple[float, float, float, float] | None":
    """``(r, g, b, alpha)`` in 0..255 / 0..1, or ``None`` if unparseable."""
    v = (value or "").strip()
    if v.startswith("#"):
        h = v[1:]
        if len(h) in (3, 4):
            h = "".join(c * 2 for c in h)
        if len(h) not in (6, 8):
            return None
        try:
            r, g, b = (int(h[i:i + 2], 16) for i in (0, 2, 4))
        except ValueError:
            return None
        a = int(h[6:8], 16) / 255 if len(h) == 8 else 1.0
        return (r, g, b, a)
    m = re.match(r"^rgba?\(([^)]*)\)$", v)
    if not m:
        return None
    parts = [p for p in re.split(r"[,\s/]+", m.group(1).strip()) if p]
    if len(parts) < 3:
        return None
    try:
        nums = [float(p.rstrip("%")) for p in parts[:4]]
    except ValueError:
        return None
    a = nums[3] if len(nums) > 3 else 1.0
    return (nums[0], nums[1], nums[2], a)


def _rel_luminance(r: float, g: float, b: float) -> float:
    def chan(c: float) -> float:
        c = c / 255.0
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
    return 0.2126 * chan(r) + 0.7152 * chan(g) + 0.0722 * chan(b)


def contrast_ratio(fg: str, bg: str) -> "float | None":
    """WCAG 2.1 contrast ratio, compositing a translucent ``fg`` over ``bg``."""
    f, b = _parse_rgb(fg), _parse_rgb(bg)
    if not f or not b:
        return None
    if f[3] < 1.0:
        f = tuple(f[i] * f[3] + b[i] * (1 - f[3]) for i in range(3)) + (1.0,)
    l1, l2 = _rel_luminance(*f[:3]), _rel_luminance(*b[:3])
    hi, lo = max(l1, l2), min(l1, l2)
    return (hi + 0.05) / (lo + 0.05)


#: Below this a text/background pair is reported as unreadable, not merely low.
CONTRAST_FAIL = 3.0
#: WCAG AA for normal body text.
CONTRAST_AA = 4.5


def audit_contrast(overrides: "dict[str, str]") -> "list[dict]":
    """Check every text token against the surface the registry pairs it with.

    Returns findings ordered worst-first. This WARNS rather than blocks: an
    operator may legitimately accept a low-contrast accent. What must never
    happen is applying an unreadable palette *without being told*, so the UI
    requires an explicit confirmation for anything below ``CONTRAST_FAIL``.
    """
    eff = dict(DEFAULTS)
    eff.update(overrides or {})
    out: "list[dict]" = []
    for name, meta in TOKENS.items():
        bg_name = meta.get("on")
        if not bg_name:
            continue
        ratio = contrast_ratio(eff[name], eff[bg_name])
        if ratio is None or ratio >= CONTRAST_AA:
            continue
        out.append({
            "token": name,
            "label": meta["label"],
            "group": meta["group"],
            "against": TOKENS[bg_name]["label"],
            "ratio": round(ratio, 2),
            "level": "fail" if ratio < CONTRAST_FAIL else "warn",
        })
    out.sort(key=lambda r: r["ratio"])
    return out


def has_unreadable(overrides: "dict[str, str]") -> bool:
    return any(f["level"] == "fail" for f in audit_contrast(overrides))


# ── CSS emission ────────────────────────────────────────────────────────────
def css_for(overrides: "dict[str, str]") -> str:
    """The ``:root`` override block for a theme, or ``""`` for the defaults.

    Re-validated here, not just at save time. The DB is not a trust boundary:
    a row could arrive from a restored backup, a replica, or a hand-edited
    ``psql`` session, and this is the last gate before the value reaches HTML.
    """
    clean, _ = validate_tokens(overrides or {})
    if not clean:
        return ""
    body = "".join("  --fw-%s: %s;\n" % (k, clean[k]) for k in TOKEN_NAMES
                   if k in clean)
    return ":root {\n%s}\n" % body


# ── active theme (cached, TTL) ──────────────────────────────────────────────
_TTL = 15.0
_cache: "dict | None" = None
_cache_ts = 0.0


def invalidate() -> None:
    """Force the next read to hit the DB (call right after any theme edit)."""
    global _cache_ts
    _cache_ts = 0.0


def _load_active() -> dict:
    from ..models_theme import UiTheme
    row = UiTheme.query.filter_by(is_active=True).first()
    if row is None:
        row = UiTheme.query.filter_by(slug=BUILTIN_SLUG).first()
    if row is None:
        return {"id": None, "name": "SATOM Classic", "slug": BUILTIN_SLUG,
                "css": "", "logo": "", "favicon": ""}
    return {"id": row.id, "name": row.name, "slug": row.slug,
            "css": css_for(row.tokens), "logo": row.logo or "",
            "favicon": row.favicon or ""}


def active_theme() -> dict:
    """``{id, name, slug, css, logo, favicon}`` for the active theme.

    Never raises: a theming failure must not be able to take down every page in
    the console, so any error degrades to the shipped stylesheet.
    """
    global _cache, _cache_ts
    if _cache is None or (time.monotonic() - _cache_ts) > _TTL:
        try:
            _cache = _load_active()
        except Exception:
            _cache = {"id": None, "name": "SATOM Classic", "slug": BUILTIN_SLUG,
                      "css": "", "logo": "", "favicon": ""}
        _cache_ts = time.monotonic()
    return _cache


def active_css() -> str:
    return active_theme().get("css", "")


def set_active(theme_id: int) -> "str | None":
    """Activate one theme. Returns an error string, or ``None`` on success."""
    from ..extensions import db
    from ..models_theme import UiTheme
    row = UiTheme.query.get(theme_id)
    if row is None:
        return "Theme not found."
    UiTheme.query.filter(UiTheme.is_active.is_(True)).update(
        {"is_active": False}, synchronize_session=False)
    row.is_active = True
    db.session.commit()
    invalidate()
    return None


def reset_to_builtin() -> str:
    """Activate the immutable built-in. The escape hatch for an unreadable UI."""
    from ..models_theme import UiTheme
    row = UiTheme.query.filter_by(slug=BUILTIN_SLUG).first()
    if row is None:
        seed_defaults()
        row = UiTheme.query.filter_by(slug=BUILTIN_SLUG).first()
    set_active(row.id)
    return row.name


# ── seeding ─────────────────────────────────────────────────────────────────
#: Shipped themes. ``SATOM Classic`` deliberately carries NO overrides: it *is*
#: the stylesheet, so it can never drift from it.
BUILTINS: "list[dict]" = [
    {
        "slug": BUILTIN_SLUG,
        "name": "SATOM Classic",
        "description": "The shipped look — deep navy chrome, Fortinet ember "
                       "accent, light content canvas.",
        "tokens": {},
    },
    {
        "slug": "satom-slate",
        "name": "SATOM Slate",
        "description": "Cooler neutral chrome with an indigo accent.",
        "tokens": {
            "sidebar-bg": "#1E293B", "sidebar-active": "#6366F1",
            "sidebar-text": "#CBD5E1", "sidebar-section": "#94A3B8",
            "topbar-bg": "#0F172A",
            "content-bg": "#F1F5F9", "surface-alt": "#F8FAFC",
            "border": "#E2E8F0", "border-light": "#EDF2F7",
            "accent": "#4F46E5", "accent-hover": "#4338CA",
            "accent-light": "rgba(79, 70, 229, 0.10)",
            "text-primary": "#0F172A", "text-secondary": "#64748B",
        },
    },
    {
        "slug": "satom-graphite",
        "name": "SATOM Graphite",
        "description": "Near-black chrome with a warm amber accent.",
        "tokens": {
            "sidebar-bg": "#23272E", "sidebar-active": "#F59E0B",
            "sidebar-text": "#C9CED6", "sidebar-section": "#8B939E",
            "topbar-bg": "#16191D",
            "content-bg": "#F5F5F4", "surface-alt": "#FAFAF9",
            "border": "#E7E5E4", "border-light": "#F0EFEE",
            "accent": "#B45309", "accent-hover": "#92400E",
            "accent-light": "rgba(180, 83, 9, 0.10)",
            "text-primary": "#1C1917", "text-secondary": "#57534E",
        },
    },
]


def seed_defaults() -> int:
    """Insert-only seed of the built-in themes; operator rows are never touched.

    Also guarantees the invariant "exactly one active theme" on a fresh install.
    """
    from ..extensions import db
    from ..models_theme import UiTheme
    existing = {t.slug for t in UiTheme.query.all()}
    added = 0
    for spec in BUILTINS:
        if spec["slug"] in existing:
            continue
        row = UiTheme(slug=spec["slug"], name=spec["name"],
                      description=spec["description"], builtin=True,
                      created_by="system")
        row.tokens = spec["tokens"]
        db.session.add(row)
        added += 1
    if added:
        db.session.commit()
    if UiTheme.query.filter_by(is_active=True).count() != 1:
        UiTheme.query.filter(UiTheme.is_active.is_(True)).update(
            {"is_active": False}, synchronize_session=False)
        base = UiTheme.query.filter_by(slug=BUILTIN_SLUG).first()
        if base is not None:
            base.is_active = True
        db.session.commit()
    if added:
        invalidate()
    return added
