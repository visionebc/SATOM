"""Fleet-wide WAF inventory — every FortiWeb this ADOM can see, in one picture.

WHY THIS IS NOT A LIVE READ
---------------------------
The obvious build is "call every appliance and aggregate", which is what
``services/fleet_objects.py`` does for its four object tables. That is right
for a browser someone opens to look up one object; it is wrong for a
statistics page. The measurement that forced the metrics rewrite on
2026-08-05 applies unchanged here: one appliance answers ``system_resource``
in ~514 ms, and a fleet of 60 FortiWebs behind a page that renders six charts
would spend ~30 s of device I/O per view, per worker, per operator.

So this module reads the **SoT** (``services/sot_store``) instead: the
content-addressed snapshot the harvest already took. Rendering this page
contacts NO appliance. The cost of that choice is that the numbers are as old
as the last harvest, which is why freshness is a first-class column here and
not a footnote — see ``STALE_AFTER_HOURS``.

WHAT IS AND IS NOT SCOPED
-------------------------
This is deliberately a FLEET page: it spans devices, the way Fleet Objects and
Architecture do, and unlike ``/artifacts/*`` (which is pinned to the session's
device + ADOM). "Fleet" still means *the fleet this console may see*: rows come
from ``models.visible_appliances()``, so maintenance devices are dropped for
operators without the permission and the FortiWeb ADOM never sees another
product's boxes. The universe is narrowed ONCE, in :func:`collect`, and every
statistic is a function of that universe — the shape §121 of ``safeguards.md``
had to retrofit onto the artifacts pages after six call sites each forgot the
filter separately.

ABSENCE IS NOT ZERO
-------------------
A device with no snapshot, or a snapshot older than ``STALE_AFTER_HOURS``, is
NOT silently dropped and NOT counted as "0 policies". It is carried in
``devices`` with ``missing`` / ``stale`` set, excluded from the denominators,
and the page states how many devices actually contributed. A fleet page that
answers "3 policies need attention" while two boxes were unreachable has
answered a different question than the one asked.
"""
from __future__ import annotations

from datetime import datetime, timedelta

from ..models import Appliance, chassis_key, chassis_tally, visible_appliances
from .cache import cache_get, cache_set
from .clone_scope import is_factory
from .device_sync import slugify

#: A harvest runs hourly. Past this age the snapshot is still shown — it is the
#: best evidence there is — but every number derived from it is marked, because
#: "the fleet is compliant" and "the fleet WAS compliant last Tuesday" are
#: different claims and only one of them is on the screen.
STALE_AFTER_HOURS: int = 26

#: Parsed snapshots are cached under the snapshot's SHA256, never under the
#: version-row id. The hash IS the content, so the key changes exactly when the
#: answer changes and a long TTL is safe. Keying on the row id looked
#: equivalent and is not: ids are re-issued whenever the index is rebuilt (a
#: restore from a bundle, a standby promoted, a test's fresh database), and a
#: cache that answers id 4 with another install's device is a page showing a
#: box that is not there. Caught by the guards, which reuse ids by design.
EXTRACT_TTL: int = 900

#: FortiWeb keeps its web protection profiles in two collections. They are NOT
#: the same object: the offline one has ~38 fields against the inline one's
#: ~68, so a protection the offline profile has no slot for must never be
#: counted as "off" for it (see :data:`PROTECTIONS` and ``applicable``).
PROFILE_COLLECTIONS: tuple[tuple[str, str], ...] = (
    ("webprotection_profile_inline", "inline"),
    ("webprotection_profile_offline", "offline"),
)

# --- protection catalogue ---------------------------------------------------
# (wpp field, label, group). Every key here was read off a LIVE profile on
# fortiweb12/13 (7.6.x) via the SoT, not from documentation: a field this
# firmware does not emit would otherwise be reported as an unfilled slot on
# every profile in the fleet, i.e. a fleet-wide gap that does not exist.
G_CORE = "Core inspection"
G_ACCESS = "Access control"
G_API = "API & schema"
G_DATA = "Content & data"
G_SESSION = "Session & identity"
G_ADVANCED = "Advanced"

PROTECTIONS: tuple[tuple[str, str, str], ...] = (
    ("signature-rule", "Signatures", G_CORE),
    ("bot-mitigate-policy", "Bot mitigation", G_CORE),
    ("advanced-bot-protection", "Advanced bot protection", G_CORE),
    ("ip-intelligence", "IP intelligence", G_CORE),
    ("application-layer-dos-prevention", "Application DoS", G_CORE),
    ("syntax-based-attack-detection", "Syntax-based detection", G_CORE),
    ("threat-score-profile", "Threat score", G_CORE),

    ("geo-block-list-policy", "Geo IP block", G_ACCESS),
    ("ip-list-policy", "IP list", G_ACCESS),
    ("url-access-policy", "URL access", G_ACCESS),
    ("custom-access-policy", "Custom access rules", G_ACCESS),
    ("allow-method-policy", "Allowed methods", G_ACCESS),
    ("http-protocol-parameter-restriction", "HTTP protocol constraints", G_ACCESS),
    ("waiting-room-policy", "Waiting room", G_ACCESS),

    ("json-validation-policy", "JSON validation", G_API),
    ("xml-validation-policy", "XML validation", G_API),
    ("openapi-validation-policy", "OpenAPI validation", G_API),
    ("graphql-validation-policy", "GraphQL validation", G_API),
    ("grpc-policy", "gRPC protection", G_API),
    ("api-management-policy", "API management", G_API),
    ("mobile-api-protection", "Mobile API protection", G_API),

    ("parameter-validation-rule", "Parameter validation", G_DATA),
    ("file-upload-policy", "File upload restriction", G_DATA),
    ("webshell-detection-policy", "Web shell detection", G_DATA),
    ("dlp-policy", "Data loss prevention", G_DATA),
    ("hidden-fields-protection", "Hidden fields", G_DATA),
    ("padding-oracle", "Padding oracle", G_DATA),

    ("cookie-security-policy", "Cookie security", G_SESSION),
    ("csrf-protection", "CSRF protection", G_SESSION),
    ("cors-protection-policy", "CORS protection", G_SESSION),
    ("http-header-security", "HTTP header security", G_SESSION),
    ("http-authen-policy", "HTTP authentication", G_SESSION),
    ("user-tracking-policy", "User tracking", G_SESSION),
    ("client-management", "Client management", G_SESSION),

    ("mitb-protection", "Man-in-the-browser", G_ADVANCED),
    ("client-side-protection-policy", "Client-side protection", G_ADVANCED),
    ("subresource-integrity-policy", "Subresource integrity", G_ADVANCED),
    ("url-encryption-policy", "URL encryption", G_ADVANCED),
    ("link-cloaking-policy", "Link cloaking", G_ADVANCED),
    ("websocket-security-policy", "WebSocket security", G_ADVANCED),
    ("site-publish-helper", "Site publish", G_ADVANCED),
)

PROTECTION_GROUPS: tuple[str, ...] = (
    G_CORE, G_ACCESS, G_API, G_DATA, G_SESSION, G_ADVANCED)

PROTECTION_LABELS: dict[str, str] = {k: lbl for k, lbl, _g in PROTECTIONS}

# --- posture ----------------------------------------------------------------
#: One policy lands in exactly ONE bucket so the doughnut adds up to the policy
#: count, but the precedence hides facts (a disabled policy may ALSO have no
#: profile), which is why :func:`stats` publishes the un-bucketed totals
#: alongside. A chart that adds to 100% is not a licence to only publish the
#: chart.
P_BLOCKING = "blocking"
P_DETECTION = "detection"
P_NOPROFILE = "no-profile"
P_DISABLED = "disabled"

POSTURE_LABELS: dict[str, str] = {
    P_BLOCKING: "Blocking",
    P_DETECTION: "Detection only",
    P_NOPROFILE: "No profile",
    P_DISABLED: "Disabled",
}
POSTURE_ORDER: tuple[str, ...] = (P_BLOCKING, P_DETECTION, P_NOPROFILE, P_DISABLED)

#: TLS versions FortiWeb still offers that no policy should be terminating on.
WEAK_TLS_FIELDS: tuple[tuple[str, str], ...] = (
    ("tls-v10", "TLS 1.0"), ("tls-v11", "TLS 1.1"))


def _on(value) -> bool:
    """Is this cmdb field FILLED / turned on?

    FortiWeb writes ``""`` for an unset object reference and the literal
    ``"disable"`` for an unset toggle; both mean the slot is empty. Anything
    else is a reference to a real object (or ``enable``) and counts as on.
    """
    return str(value or "").strip().lower() not in ("", "disable")


def _text(row: dict, *keys: str) -> str:
    for k in keys:
        v = row.get(k)
        if v not in (None, ""):
            return str(v).strip()
    return ""


def _parse_dt(value: str):
    try:
        return datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# extraction — a PURE function of one snapshot
# ---------------------------------------------------------------------------
def extract(snapshot: dict) -> dict:
    """Normalise ONE device snapshot into WAF rows.

    Pure and side-effect free on purpose: the tests drive it with a literal
    dict, and :func:`collect` can memoise its result under the SoT version id
    precisely because the same blob always produces the same answer.
    """
    sections = (snapshot or {}).get("sections") or {}

    def sub(section: str, key: str) -> list[dict]:
        block = sections.get(section) or {}
        rows = block.get(key) if isinstance(block, dict) else None
        return [r for r in rows if isinstance(r, dict)] if isinstance(rows, list) else []

    # --- profiles --------------------------------------------------------
    profiles: list[dict] = []
    by_name: dict[str, dict] = {}
    for coll, kind in PROFILE_COLLECTIONS:
        for raw in sub("Web Protection", coll):
            name = _text(raw, "name", "mkey")
            if not name:
                continue
            # A slot the profile HAS NO KEY FOR is not an unfilled slot. The
            # offline profile carries ~38 of the 41 protections; counting the
            # missing three as "off" would invent a fleet-wide gap.
            applicable = [k for k, _l, _g in PROTECTIONS if k in raw]
            filled = [k for k in applicable if _on(raw.get(k))]
            entry = {
                "name": name,
                "kind": kind,
                "predefined": is_factory(raw),
                "comment": _text(raw, "comment"),
                "signature_rule": _text(raw, "signature-rule"),
                "applicable": applicable,
                "filled": filled,
                "n_applicable": len(applicable),
                "n_filled": len(filled),
                "used_by": 0,          # filled in below, from the policies
            }
            profiles.append(entry)
            # Inline wins a name collision with offline: a server policy names
            # a profile without saying which collection it came from, and the
            # inline one is what an inline-mode policy resolves.
            if name not in by_name or kind == "inline":
                by_name[name] = entry

    # --- server policies -------------------------------------------------
    policies: list[dict] = []
    for raw in sub("Server Policy", "server_policy"):
        name = _text(raw, "name", "mkey")
        if not name:
            continue
        wpp = _text(raw, "web-protection-profile")
        prof = by_name.get(wpp) if wpp else None
        enabled = str(raw.get("status", "")).strip().lower() != "disable"
        detection = _on(raw.get("monitor-mode"))
        ssl_on = _on(raw.get("ssl"))
        weak = [label for field, label in WEAK_TLS_FIELDS if _on(raw.get(field))] \
            if ssl_on else []

        if not enabled:
            posture = P_DISABLED
        elif not wpp:
            posture = P_NOPROFILE
        elif detection:
            posture = P_DETECTION
        else:
            posture = P_BLOCKING

        policies.append({
            "name": name,
            "status": "enable" if enabled else "disable",
            "enabled": enabled,
            "detection_only": detection,
            "posture": posture,
            "service": _text(raw, "service") or _text(raw, "protocol"),
            "deployment": _text(raw, "deployment-mode"),
            "vserver": _text(raw, "vserver"),
            "pool": _text(raw, "server-pool"),
            "wpp": wpp,
            # A policy naming a profile the snapshot does not contain is NOT
            # the same as a policy naming none: the first is a dangling
            # reference the operator cannot see from the device page.
            "wpp_resolved": bool(prof),
            "wpp_kind": prof["kind"] if prof else "",
            "wpp_predefined": bool(prof and prof["predefined"]),
            "protections": list(prof["filled"]) if prof else [],
            "n_protections": prof["n_filled"] if prof else 0,
            "signature_rule": prof["signature_rule"] if prof else "",
            "ssl": ssl_on,
            "certificate": _text(raw, "certificate", "certificate-group"),
            "weak_tls": weak,
            "http2": _on(raw.get("http2")),
            "scripting": _on(raw.get("scripting")),
            "comment": _text(raw, "comment"),
        })
        if prof is not None:
            prof["used_by"] += 1

    return {
        "policies": policies,
        "profiles": profiles,
        "counts": {
            "policies": len(policies),
            "vservers": len(sub("Server Objects", "vserver")),
            "pools": len(sub("Server Objects", "server_pool")),
            "profiles": len(profiles),
            "profiles_custom": sum(1 for p in profiles if not p["predefined"]),
            "signature_policies": len(sub("Web Protection", "signature")),
            "certificates": len(sub("System", "certificate")),
            "custom_rules": len(sub("Web Protection", "custom_rule")),
            "objects": int((snapshot or {}).get("total_objects") or 0),
        },
    }


# ---------------------------------------------------------------------------
# collection — the UNIVERSE, narrowed once
# ---------------------------------------------------------------------------
def fortiweb_scopes(user=None) -> list:
    """THE universe of every ``/waf/*`` page — narrowed exactly once, here.

    ``visible_appliances`` already applies the console's ADOM and the
    maintenance permission; the ``kind`` filter is what keeps the GLOBAL
    console — where the fleet legitimately means every product — from counting
    a FortiADC's objects as WAF configuration.

    Callers that need the ORM rows (``services.waf_artifact_fleet`` feeds them
    to ``artifact_stats.fleet_stats``) take them from here rather than
    re-deriving the query: six call sites each forgetting the filter separately
    is precisely what safeguards §121 had to retrofit onto ``/artifacts/*``.
    """
    return (visible_appliances(user=user)
            .filter(Appliance.kind == "fortiweb")
            .order_by(Appliance.name).all())


def collect(user=None) -> dict:
    """Every visible FortiWeb scope, with its policies and profiles.

    The returned dict is the only universe the views are allowed to read: a
    section computed from anything else can widen the page past what this
    console may see.
    """
    from . import sot_store

    rows = fortiweb_scopes(user=user)

    devices: list[dict] = []
    policies: list[dict] = []
    profiles: list[dict] = []
    now = datetime.utcnow()

    for appl in rows:
        scope = scope_label(appl)
        dev = {
            "appliance_id": appl.id,
            "name": appl.name,
            "scope": scope,
            "device": device_name(appl),
            "adom": (appl.vdom or "").strip(),
            "host": appl.host,
            "model": appl.model or "",
            "firmware": appl.firmware or "",
            "maintenance": bool(appl.maintenance),
            "chassis": chassis_key(appl) or ("appliance:%s" % appl.id),
            "slug": slugify(appl.name),
            "missing": True,
            "stale": False,
            "age_hours": None,
            "harvested_at": "",
            "changed_at": "",
            "version_id": None,
            "counts": {},
            "policies": 0,
        }
        hist = sot_store.history(device=dev["slug"], limit=1)
        row = hist[0] if hist else None
        if row and row.get("id"):
            seen = _parse_dt(row.get("last_seen_at") or row.get("taken_at"))
            age = (now - seen).total_seconds() / 3600.0 if seen else None
            data = _extract_cached(appl.id, int(row["id"]), row.get("sha256") or "")
            if data is not None:
                dev.update({
                    "missing": False,
                    "version_id": int(row["id"]),
                    "harvested_at": row.get("last_seen_at") or "",
                    "changed_at": row.get("taken_at") or "",
                    "age_hours": round(age, 1) if age is not None else None,
                    "stale": bool(age is not None and age > STALE_AFTER_HOURS),
                    "counts": data["counts"],
                    "policies": data["counts"]["policies"],
                })
                for p in data["policies"]:
                    policies.append(dict(p, scope=scope, appliance_id=appl.id,
                                         device=dev["device"], adom=dev["adom"]))
                for p in data["profiles"]:
                    profiles.append(dict(p, scope=scope, appliance_id=appl.id,
                                         device=dev["device"], adom=dev["adom"]))
        devices.append(dev)

    chassis, adoms = chassis_tally(rows)
    return {
        "devices": devices,
        "policies": policies,
        "profiles": profiles,
        "chassis": chassis,
        "adoms": adoms,
        "reporting": [d for d in devices if not d["missing"]],
        "generated_at": now.isoformat(timespec="seconds"),
    }


def device_name(appl) -> str:
    """The BOX's name, without the ADOM suffix the registration carries."""
    name = appl.name or ""
    return name.split("@", 1)[0] if "@" in name else name


def scope_label(appl) -> str:
    """How this row is named everywhere on the page: ``device / ADOM``."""
    adom = (appl.vdom or "").strip()
    return "%s / %s" % (device_name(appl), adom) if adom else device_name(appl)


def _extract_cached(appliance_id: int, version_id: int,
                    sha256: str) -> dict | None:
    key = ("waf:extract:%s" % sha256) if sha256 else ""
    if key:
        hit = cache_get(appliance_id, key)
        if hit is not None:
            return hit
    from . import sot_store
    snap = sot_store.load(version_id)
    if snap is None:
        return None
    data = extract(snap)
    # No hash, no cache. Falling back to the row id here would put the exact
    # collision this key exists to avoid back into the one path that takes it.
    if key:
        cache_set(appliance_id, key, data, ttl=EXTRACT_TTL)
    return data


# ---------------------------------------------------------------------------
# statistics
# ---------------------------------------------------------------------------
def stats(universe: dict) -> dict:
    """Every number the overview prints, derived from *universe* alone."""
    devices = universe["devices"]
    policies = universe["policies"]
    profiles = universe["profiles"]
    reporting = universe["reporting"]

    posture = {k: 0 for k in POSTURE_ORDER}
    for p in policies:
        posture[p["posture"]] += 1

    ssl_on = [p for p in policies if p["ssl"]]
    weak_tls = [p for p in ssl_on if p["weak_tls"]]
    # A certificate is only expected where TLS is terminated. Counting "no
    # certificate" over plain-HTTP policies would report the whole fleet as
    # broken for doing exactly the right thing.
    no_cert = [p for p in ssl_on if not p["certificate"]]

    used = {(p["scope"], p["wpp"]) for p in policies if p["wpp"]}
    orphans = [p for p in profiles
               if not p["predefined"] and (p["scope"], p["name"]) not in used]
    dangling = [p for p in policies if p["wpp"] and not p["wpp_resolved"]]

    # Coverage is counted ONCE per policy, not once per (protection, policy):
    # the naive nesting is O(protections x policies x profiles) and the target
    # fleet is 60 boxes x ~750 policies. Index first, then tally.
    applicable_of = _applicable_index(profiles)
    n_applicable = {key: 0 for key, _l, _g in PROTECTIONS}
    n_on = {key: 0 for key, _l, _g in PROTECTIONS}
    for pol in policies:
        if not pol.get("wpp_resolved"):
            continue
        slots = applicable_of.get((pol["scope"], pol["wpp"]), ())
        filled = set(pol["protections"])
        for key in slots:
            n_applicable[key] += 1
            if key in filled:
                n_on[key] += 1

    coverage = [{
        "key": key, "label": label, "group": group,
        "applicable": n_applicable[key], "on": n_on[key],
        "pct": (round(100.0 * n_on[key] / n_applicable[key], 1)
                if n_applicable[key] else None),
    } for key, label, group in PROTECTIONS]

    by_scope: dict[str, dict[str, int]] = {}
    for p in policies:
        slot = by_scope.setdefault(p["scope"], {k: 0 for k in POSTURE_ORDER})
        slot[p["posture"]] += 1
    per_scope = [{
        "scope": d["scope"],
        "missing": d["missing"],
        "stale": d["stale"],
        "total": sum(by_scope.get(d["scope"], {}).values()),
        **{k: by_scope.get(d["scope"], {}).get(k, 0) for k in POSTURE_ORDER},
    } for d in devices]

    signatures: dict[str, int] = {}
    for p in policies:
        if p["posture"] == P_DISABLED:
            continue
        signatures[p["signature_rule"] or "— none —"] = \
            signatures.get(p["signature_rule"] or "— none —", 0) + 1

    return {
        "chassis": universe["chassis"],
        "adoms": universe["adoms"],
        "scopes": len(devices),
        "reporting": len(reporting),
        "missing": sum(1 for d in devices if d["missing"]),
        "stale": sum(1 for d in devices if d["stale"]),
        "policies": len(policies),
        "vservers": sum(d["counts"].get("vservers", 0) for d in reporting),
        "pools": sum(d["counts"].get("pools", 0) for d in reporting),
        "certificates": sum(d["counts"].get("certificates", 0) for d in reporting),
        "custom_rules": sum(d["counts"].get("custom_rules", 0) for d in reporting),
        "profiles": len(profiles),
        "profiles_custom": sum(1 for p in profiles if not p["predefined"]),
        "posture": posture,
        # UN-BUCKETED totals: the doughnut assigns one bucket per policy, so a
        # disabled policy that ALSO has no profile is invisible in it.
        "detection_any": sum(1 for p in policies if p["detection_only"]),
        "no_profile_any": sum(1 for p in policies if not p["wpp"]),
        "disabled_any": sum(1 for p in policies if not p["enabled"]),
        "ssl": len(ssl_on),
        "plain": len(policies) - len(ssl_on),
        "weak_tls": len(weak_tls),
        "no_cert": len(no_cert),
        "orphan_profiles": len(orphans),
        "dangling": len(dangling),
        "coverage": coverage,
        "per_scope": per_scope,
        "signatures": sorted(signatures.items(), key=lambda kv: (-kv[1], kv[0])),
        "generated_at": universe["generated_at"],
    }


def _applicable_index(profiles: list[dict]) -> dict[tuple[str, str], tuple[str, ...]]:
    """``(scope, profile name) -> the protection slots that profile HAS``.

    Keyed by scope as well as name because two devices may both own a profile
    called ``wpp-portal`` and they are different objects; a name-only index
    would let one box's inline profile answer for another box's offline one.

    A policy with no resolvable profile has no applicable slots at all — it is
    not "0% covered", it is outside the question, and it is already counted as
    ``no-profile`` where that fact belongs.
    """
    index: dict[tuple[str, str], tuple[str, ...]] = {}
    for prof in profiles:
        key = (prof["scope"], prof["name"])
        # Same precedence as ``extract``: inline wins, so the index agrees with
        # the profile the policy actually resolved.
        if key not in index or prof["kind"] == "inline":
            index[key] = tuple(prof["applicable"])
    return index


def change_series(universe: dict, days: int = 30) -> dict:
    """SoT versions minted per day for these devices — config churn over time.

    Reads the version INDEX only (never a blob): the row exists precisely
    because that device's configuration changed, so this is a change timeline,
    not a harvest timeline. An unchanged fleet draws a flat zero, which is the
    correct picture and not a broken chart.
    """
    from ..models_sot import SotVersion

    slugs = [d["slug"] for d in universe["devices"]]
    labels: list[str] = []
    day = datetime.utcnow().date() - timedelta(days=max(1, days) - 1)
    while len(labels) < max(1, days):
        labels.append(day.isoformat())
        day += timedelta(days=1)

    counts = {lbl: 0 for lbl in labels}
    if slugs:
        since = datetime.utcnow() - timedelta(days=max(1, days))
        rows = (SotVersion.query
                .filter(SotVersion.device.in_(slugs),
                        SotVersion.taken_at >= since).all())
        for row in rows:
            key = row.taken_at.date().isoformat() if row.taken_at else ""
            if key in counts:
                counts[key] += 1
    return {"labels": labels, "values": [counts[lbl] for lbl in labels]}
