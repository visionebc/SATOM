"""Fleet → WAF — the export bundle: pick the contents, pick the formats, get a ZIP.

WHAT THIS IS FOR
----------------
Every ``/waf/*`` page answers its question on screen and each one already
offers a CSV of the table you are looking at. What none of them could do is
hand somebody the whole picture — policies, profiles, coverage, artifacts,
carve-outs and the numbers behind the six charts — in one file, in a format
that opens on a laptop with no SATOM on it.

THE PROPERTY THAT SHAPES EVERYTHING ELSE: PROVENANCE TRAVELS
------------------------------------------------------------
An export is a snapshot OF A SNAPSHOT. The pages read the source-of-truth
store, so their figures are exactly as old as the last harvest — which is why
each page carries a scope-and-freshness banner as its denominator, not as a
footnote (see ``templates/waf/_header.html``).

A spreadsheet in someone's mail has NO banner. Left alone it becomes a document
that outlives its own truth, and the person reading it three weeks later has no
way to know. So every artefact this module emits carries the same four facts:

  * when it was generated, and by whom,
  * how many device/ADOM scopes it covers **and how many actually reported**,
  * which scopes are stale or were never harvested, BY NAME,
  * what each dataset is a statement about.

``MANIFEST.txt`` is at the root of the ZIP, the workbook opens on a
*Scope & freshness* sheet before any data sheet, and the PDF's first page is
that same block. Not three authors: one :func:`provenance` call.

WHAT THE FILTERS DO NOT DO
--------------------------
The bundle is ALWAYS the whole visible fleet. The per-page ``?format=csv``
link is the one that exports "exactly the rows you filtered" and says so in its
tooltip. Giving the ZIP a second, invisible narrowing is how a file called
``waf_fleet_policies.csv`` ends up holding one ADOM — the §119 drift with a
longer fuse, because here nobody can see the filter bar the file came from.

EXCEPTIONS ARE DESIRED STATE, NOT DEVICE STATE
----------------------------------------------
Carve-outs live in the manager DB. Verified against ``models.WppException``:
there is **no column recording whether one was ever pushed to a box** —
``exception_inject.apply_injection`` returns its steps to the caller and stores
nothing. So this module never implies deployment. It reports what was authored,
against what the last snapshot of that scope actually contains, and labels the
whole dataset accordingly. A row that says "exception exists" would otherwise be
read as "the box is carved out", which is a claim SATOM cannot make.

WHY THERE IS NO BROWSER IN HERE
-------------------------------
The charts are re-rendered server-side through ``services/pdf_kit`` from the
SAME payload ``/waf/api/summary.json`` serves the on-screen Chart.js. Capturing
``canvas.toDataURL()`` from the client would have been fewer lines and would
have made the export impossible from anywhere but a browser with the page open
— no scheduled report, no CLI, and a blank image for any chart that had failed
to fetch, which on a canvas is indistinguishable from a chart of zeros.
"""
from __future__ import annotations

import csv
import io
import json
import zipfile
from datetime import datetime
from typing import Any, Callable, Iterable, Sequence

from . import pdf_kit
from . import waf_artifact_fleet as artsvc
from . import waf_fleet as svc
from . import xlsx_writer

# ---------------------------------------------------------------------------
# Look
# ---------------------------------------------------------------------------
# THE PAGE IS LIGHT and so is the PDF. These are the .fw-badge-* values, the
# ones calibrated against white (safeguards §9m) — the fleet's dark-theme
# pastels drop to ~1.4:1 here. They are duplicated from static/js/waf.js
# because a constant cannot cross the Python/JS boundary; the duplication is
# held together by a guard (test_waf_export) that reads both files and fails
# when they drift, which is a mechanism rather than a comment promising they
# match.
BADGE = {
    "green": "#15692A", "amber": "#7A5700", "red": "#8B1C2A",
    "grey": "#3D4550", "purple": "#4C2A85", "blue": "#1D4ED8",
    "accent": "#EF5424",
}
POSTURE_COLOURS = {
    svc.P_BLOCKING: BADGE["green"], svc.P_DETECTION: BADGE["amber"],
    svc.P_NOPROFILE: BADGE["red"], svc.P_DISABLED: BADGE["grey"],
}
SERIES_PALETTE = [BADGE["blue"], BADGE["purple"], BADGE["green"],
                  BADGE["amber"], BADGE["red"], BADGE["grey"],
                  BADGE["accent"]]

#: Rows of a table that reach the PDF. Beyond this it stops being a document a
#: human reads and the CSV/XLSX in the same ZIP is the answer — the footnote
#: under every truncated table says exactly that.
PDF_TABLE_ROWS = 40
PDF_CHART_POINTS = 24

FORMATS: tuple[tuple[str, str], ...] = (
    ("csv", "CSV (one file per dataset)"),
    ("xlsx", "Excel workbook (.xlsx)"),
    ("pdf", "PDF report (with charts)"),
)


# ---------------------------------------------------------------------------
# Columns — screen, CSV, sheet and PDF table all read from ONE definition
# ---------------------------------------------------------------------------
EXCEPTION_COLUMNS: tuple[tuple[str, str], ...] = (
    ("scope", "Device / ADOM"),
    ("category", "Kind"),
    ("type_label", "Type"),
    ("name", "Name"),
    ("wpp", "Web protection profile"),
    ("wpp_state", "Profile in snapshot"),
    ("wpp_used_by", "Policies binding that profile"),
    ("policies", "Authored for policies"),
    ("policies_state", "Policies in snapshot"),
    ("enabled", "Enabled"),
    ("stale", "Stale"),
    ("stale_reason", "Why stale"),
    ("reason", "Operator reason"),
    ("payload", "Payload"),
    ("author", "Author"),
    ("created_at", "Created"),
    ("updated_at", "Updated"),
)

SCOPE_COLUMNS: tuple[tuple[str, str], ...] = (
    ("scope", "Device / ADOM"),
    ("device", "Device"),
    ("adom", "ADOM"),
    ("model", "Model"),
    ("firmware", "Firmware"),
    ("state", "Snapshot"),
    ("age_hours", "Age (hours)"),
    ("harvested_at", "Last seen"),
    ("changed_at", "Last change"),
    ("policies", "Server policies"),
    ("maintenance", "Maintenance"),
)

SUMMARY_COLUMNS: tuple[tuple[str, str], ...] = (
    ("group", "Section"),
    ("metric", "Figure"),
    ("value", "Value"),
    ("note", "What it counts"),
)

CHART_COLUMNS: tuple[tuple[str, str], ...] = (
    ("chart", "Chart"),
    ("label", "Series label"),
    ("value", "Value"),
    ("unit", "Unit"),
)


# ---------------------------------------------------------------------------
# The bundle context — every dataset is a function of ONE narrowing
# ---------------------------------------------------------------------------
class Bundle:
    """Lazily-built universes, so an unticked dataset costs nothing.

    ``waf_fleet.collect`` walks the SoT index and decompresses a snapshot per
    scope; ``waf_artifact_fleet.collect`` reads three whole tables. Building
    both for a PDF of one page would double the cost of every export. They are
    computed on first touch and reused for every format — so a CSV+XLSX+PDF
    bundle reads the estate ONCE, and the three files cannot disagree.
    """

    def __init__(self, user=None, now: datetime | None = None):
        self.user = user
        self.now = now or datetime.utcnow()
        self._waf: dict | None = None
        self._art: dict | None = None
        self._exc: list[dict] | None = None

    # -- universes --------------------------------------------------------
    @property
    def waf(self) -> dict:
        if self._waf is None:
            self._waf = svc.collect(user=self.user)
        return self._waf

    @property
    def art(self) -> dict:
        if self._art is None:
            self._art = artsvc.collect(user=self.user)
        return self._art

    @property
    def stats(self) -> dict:
        return svc.stats(self.waf)

    @property
    def art_stats(self) -> dict:
        return artsvc.stats(self.art)

    @property
    def exceptions(self) -> list[dict]:
        if self._exc is None:
            self._exc = exception_rows(self.waf, user=self.user)
        return self._exc


# ---------------------------------------------------------------------------
# Exceptions — the fleet view that has no page of its own (yet)
# ---------------------------------------------------------------------------
def exception_rows(universe: dict, user=None) -> list[dict]:
    """Every authored carve-out in the visible fleet, joined to its WPP.

    Narrowed by ``waf_fleet.fortiweb_scopes`` — the SAME single call every
    other ``/waf/*`` section is a function of. Re-deriving visibility here is
    what §121 had to retrofit onto six call sites in the artifacts pages.

    The three joins that make the row worth exporting, and the trap in each:

    * ``wpp_state`` — does the named profile exist in that scope's snapshot?
      A scope with NO snapshot answers **unknown**, never "missing": we have no
      evidence either way, and printing "missing" would send an operator to
      re-author a carve-out that is perfectly fine.
    * ``wpp_used_by`` — how many server policies in that scope bind the
      profile. That is the blast radius of the carve-out, and it is the number
      the Exceptions page exists to surface (a WPP is usually SHARED).
    * ``policies_state`` — are the policies it was authored for still in the
      configuration? Same unknown-vs-missing rule.
    """
    from ..models import WppException
    from . import wpp_exceptions as store

    appliances = svc.fortiweb_scopes(user=user)
    scope_of = {a.id: svc.scope_label(a) for a in appliances}
    if not scope_of:
        return []

    # Which scopes we can actually make a statement about. A device that never
    # reported is not a device with zero profiles.
    reporting = {d["scope"] for d in universe["devices"] if not d["missing"]}
    profile_names = {(p["scope"], p["name"]) for p in universe["profiles"]}
    policy_names = {(p["scope"], p["name"]) for p in universe["policies"]}
    binders: dict[tuple[str, str], int] = {}
    for p in universe["policies"]:
        if p["wpp"]:
            key = (p["scope"], p["wpp"])
            binders[key] = binders.get(key, 0) + 1

    try:
        found = (WppException.query
                 .filter(WppException.appliance_id.in_(list(scope_of)))
                 .all())
    except Exception:  # noqa: BLE001 — table may not exist on a fresh install
        return []

    rows: list[dict] = []
    for exc in found:
        scope = scope_of.get(exc.appliance_id)
        if scope is None:                      # not visible here — never leak
            continue
        known = scope in reporting
        wpp = (exc.wpp_mkey or "").strip()
        if not wpp:
            wpp_state = "not bound to a profile"
        elif not known:
            wpp_state = "unknown — scope never harvested"
        else:
            wpp_state = ("present" if (scope, wpp) in profile_names
                         else "NOT in snapshot")

        authored = exc.policy_names
        if not authored:
            pol_state = "not bound to a policy"
        elif not known:
            pol_state = "unknown — scope never harvested"
        else:
            gone = [p for p in authored if (scope, p) not in policy_names]
            pol_state = ("all present" if not gone
                         else "NOT in snapshot: " + ", ".join(gone))

        spec = store.type_for(exc.exc_type) or {}
        rows.append({
            "scope": scope,
            "appliance_id": exc.appliance_id,
            "category": exc.category,
            "exc_type": exc.exc_type,
            "type_label": spec.get("label") or exc.exc_type,
            "group": spec.get("group") or "",
            "name": exc.name or "",
            "wpp": wpp,
            "wpp_state": wpp_state,
            "wpp_used_by": binders.get((scope, wpp), 0) if wpp and known else "",
            "policies": ", ".join(authored),
            "policies_state": pol_state,
            "enabled": "yes" if exc.enabled else "no",
            "stale": "yes" if exc.stale else "no",
            "stale_reason": exc.stale_reason or "",
            "reason": exc.reason or "",
            # Compact, sorted: the payload is the carve-out's actual content
            # and an export that drops it cannot be used to re-author one.
            "payload": json.dumps(exc.payload_dict, sort_keys=True,
                                  separators=(",", ":")),
            "author": exc.author or "",
            "created_at": _dt(exc.created_at),
            "updated_at": _dt(exc.updated_at),
        })
    rows.sort(key=lambda r: (r["scope"], r["category"], r["type_label"],
                             r["name"], r["wpp"]))
    return rows


def _dt(value) -> str:
    return value.isoformat(timespec="seconds") if value else ""


# ---------------------------------------------------------------------------
# Dataset builders
# ---------------------------------------------------------------------------
def _policies(b: Bundle) -> list[dict]:
    out = []
    for p in b.waf["policies"]:
        out.append(dict(
            p,
            posture_label=svc.POSTURE_LABELS.get(p["posture"], p["posture"]),
            ssl_text=("TLS " + "/".join(p["weak_tls"]) if p["weak_tls"]
                      else ("TLS" if p["ssl"] else "plain HTTP")),
            protection_list=", ".join(
                svc.PROTECTION_LABELS.get(k, k) for k in p["protections"]),
        ))
    out.sort(key=lambda r: (r["scope"], r["name"]))
    return out


def _profiles(b: Bundle) -> list[dict]:
    used = {(p["scope"], p["wpp"]) for p in b.waf["policies"] if p["wpp"]}
    out = [dict(prof,
                origin="predefined" if prof["predefined"] else "custom",
                orphan=("yes" if (not prof["predefined"]
                                  and (prof["scope"], prof["name"]) not in used)
                        else "no"),
                protection_list=", ".join(
                    svc.PROTECTION_LABELS.get(k, k) for k in prof["filled"]))
           for prof in b.waf["profiles"]]
    out.sort(key=lambda r: (r["scope"], r["name"]))
    return out


def _coverage(b: Bundle) -> list[dict]:
    """Protection x scope, as LONG rows.

    The screen renders a matrix because an operator scans across it. A matrix
    exported wide gives one column per device, so the header changes shape with
    the fleet and no two exports can be diffed or stacked. Long format keeps a
    stable header — and ``applicable`` is carried beside ``on`` so a slot the
    profile does not HAVE stays distinguishable from one that is switched off.
    That distinction is the whole reason the on-screen matrix paints a grey
    dash instead of a red zero.
    """
    index = svc._applicable_index(b.waf["profiles"])  # noqa: SLF001
    cells: dict[tuple[str, str], dict[str, int]] = {}
    for pol in b.waf["policies"]:
        if not pol.get("wpp_resolved"):
            continue
        filled = set(pol["protections"])
        for key in index.get((pol["scope"], pol["wpp"]), ()):
            cell = cells.setdefault((key, pol["scope"]), {"on": 0, "applicable": 0})
            cell["applicable"] += 1
            if key in filled:
                cell["on"] += 1

    scopes = [d["scope"] for d in b.waf["devices"] if not d["missing"]]
    rows = []
    for key, label, group in svc.PROTECTIONS:
        for scope in scopes:
            cell = cells.get((key, scope))
            rows.append({
                "protection": label, "group": group, "scope": scope,
                "on": cell["on"] if cell else 0,
                "applicable": cell["applicable"] if cell else 0,
                "pct": (round(100.0 * cell["on"] / cell["applicable"], 1)
                        if cell and cell["applicable"] else ""),
                "verdict": _cov_verdict(cell),
            })
    return rows


def _cov_verdict(cell) -> str:
    if not cell or not cell["applicable"]:
        return "not applicable here"
    if cell["on"] == cell["applicable"]:
        return "on everywhere"
    return "off on %d of %d" % (cell["applicable"] - cell["on"],
                                cell["applicable"])


def _artifacts(b: Bundle) -> list[dict]:
    # ``policies`` / ``profiles`` are COUNTS on the row and stay counts — the
    # names go in their own column. Overwriting the count with a joined string
    # would give the export a different meaning for a column the /waf/artifacts
    # table already publishes as a number.
    rows = [dict(r,
                 recoverable=("yes" if r["readable"] else "no — upload only"),
                 policy_list=", ".join(r["policy_names"][:8]),
                 empty_flag="yes" if r["empty"] else "no")
            for r in b.art["rows"]]
    rows.sort(key=lambda r: (r["scope"], r["label"], r["name"]))
    return rows


def _scopes(b: Bundle) -> list[dict]:
    out = []
    for d in b.waf["devices"]:
        out.append(dict(
            d,
            state=("never harvested" if d["missing"]
                   else ("stale" if d["stale"] else "fresh")),
            maintenance="yes" if d["maintenance"] else "no",
            age_hours="" if d["age_hours"] is None else d["age_hours"],
        ))
    out.sort(key=lambda r: r["scope"])
    return out


def _summary(b: Bundle) -> list[dict]:
    """The KPI tiles, as rows. What the charts are drawn FROM lives in
    :func:`chart_rows`; this is what the headline numbers say."""
    s = b.stats
    rows = [
        ("Scope", "Device/ADOM scopes visible", s["scopes"],
         "the denominator of every figure below"),
        ("Scope", "Scopes reporting a snapshot", s["reporting"],
         "the rest contribute nothing — they are not zeros"),
        ("Scope", "Scopes never harvested", s["missing"], ""),
        ("Scope", "Scopes with a stale snapshot", s["stale"],
         "newest snapshot older than %dh" % svc.STALE_AFTER_HOURS),
        ("Policies", "Server policies", s["policies"], ""),
        ("Policies", "Blocking", s["posture"][svc.P_BLOCKING],
         "enabled, has a profile, not in monitor mode"),
        ("Policies", "Monitor mode only", s["posture"][svc.P_DETECTION],
         "detects and logs; blocks nothing"),
        ("Policies", "No protection profile", s["posture"][svc.P_NOPROFILE], ""),
        ("Policies", "Disabled", s["posture"][svc.P_DISABLED], ""),
        ("Policies", "Monitor mode (un-bucketed)", s["detection_any"],
         "the doughnut puts each policy in ONE bucket; these totals overlap"),
        ("Policies", "No profile (un-bucketed)", s["no_profile_any"], ""),
        ("Policies", "Disabled (un-bucketed)", s["disabled_any"], ""),
        ("Transport", "TLS terminated", s["ssl"], ""),
        ("Transport", "TLS 1.0/1.1 enabled", s["weak_tls"],
         "deprecated protocol versions still switched on"),
        ("Transport", "Plain HTTP", s["plain"], ""),
        ("Transport", "TLS without a certificate", s["no_cert"],
         "counted over TLS policies only"),
        ("Profiles", "Web protection profiles", s["profiles"], ""),
        ("Profiles", "Custom (not factory)", s["profiles_custom"], ""),
        ("Profiles", "Orphaned custom profiles", s["orphan_profiles"],
         "no server policy binds them"),
        ("Profiles", "Dangling profile references", s["dangling"],
         "a policy names a profile the snapshot does not contain"),
        ("Objects", "Virtual servers", s["vservers"], ""),
        ("Objects", "Server pools", s["pools"], ""),
        ("Objects", "Certificates", s["certificates"], ""),
        ("Objects", "Custom rules", s["custom_rules"], ""),
    ]
    for c in s["coverage"]:
        rows.append(("Coverage", c["label"],
                     "%d/%d" % (c["on"], c["applicable"]),
                     "" if c["pct"] is None else "%s%% of applicable" % c["pct"]))
    return [{"group": g, "metric": m, "value": v, "note": n}
            for g, m, v, n in rows]


def _artifact_summary(b: Bundle) -> list[dict]:
    """The artifact tiles, in the SAME shape as :func:`_summary`.

    Groups are prefixed so the two can share one sheet without a reader having
    to guess whether "Scope" means the configuration scopes or the swept ones —
    the artifact page covers the same appliances but a different question, and
    the sweep has its own blind spot.
    """
    s = b.art_stats
    rows = [
        ("Scopes", "Scopes covered", s["scopes"], ""),
        ("Scopes", "Scopes never swept", s["unswept"],
         "no artifact walk has run there — their objects are in NO figure here"),
        ("Demand", "(scope, object) pairs needed", s["needed"],
         "the migration unit"),
        ("Demand", "Distinct files needed", s["distinct"], ""),
        ("Demand", "Server policies never walked", s["unwalked"],
         "of %s in configuration — the blind spot, as a number" % s["in_config"]),
        ("Readiness", "Held here", s.get("ok", 0),
         "a copy scoped to that very appliance"),
        ("Readiness", "Borrowed from another box", s.get("borrowed", 0),
         "would be copied from a device that is not in the story"),
        ("Readiness", "Backed by the shared library", s["library_backed"],
         "of the borrowed ones — a deliberate arrangement, not a guess"),
        ("Readiness", "At risk", s.get("at-risk", 0), ""),
        ("Readiness", "Blocked", s.get("blocked", 0),
         "cannot be migrated: no copy and the device will not return one"),
        ("Readiness", "Held but EMPTY", s["empty"],
         "0 bytes — answers YES to every do-we-have-it check and configures nothing"),
        ("Store", "Versions stored", s["store_versions"], ""),
        ("Store", "Bytes stored", s["store_bytes"], ""),
        ("Store", "Orphaned copies", s.get("orphan", 0),
         "held but no walked policy names them"),
    ]
    return [{"group": "Artifacts — " + g, "metric": m, "value": v, "note": n}
            for g, m, v, n in rows]


# ---------------------------------------------------------------------------
# Charts — ONE definition, drawn into the PDF and tabulated into CSV/XLSX
# ---------------------------------------------------------------------------
class ChartSpec:
    __slots__ = ("key", "title", "viz", "unit", "dataset", "series", "note")

    def __init__(self, key: str, title: str, viz: str, dataset: str,
                 series: Callable[[Bundle], tuple], *, unit: str = "policies",
                 note: str = ""):
        self.key, self.title, self.viz = key, title, viz
        self.dataset, self.series, self.unit, self.note = dataset, series, unit, note


def _s_posture(b: Bundle):
    s = b.stats
    labels = [svc.POSTURE_LABELS[k] for k in svc.POSTURE_ORDER]
    values = [s["posture"][k] for k in svc.POSTURE_ORDER]
    return labels, values, [POSTURE_COLOURS[k] for k in svc.POSTURE_ORDER]


def _s_per_scope(b: Bundle):
    rows = [r for r in b.stats["per_scope"] if r["total"]]
    return ([r["scope"] for r in rows], [r["total"] for r in rows],
            [BADGE["blue"]] * len(rows))


def _s_coverage(b: Bundle):
    rows = [c for c in b.stats["coverage"] if c["applicable"]]
    rows.sort(key=lambda c: (c["pct"] if c["pct"] is not None else -1))
    return ([c["label"] for c in rows], [c["pct"] or 0 for c in rows],
            [(BADGE["red"] if (c["pct"] or 0) < 34 else
              BADGE["amber"] if (c["pct"] or 0) < 67 else BADGE["green"])
             for c in rows])


def _s_crypto(b: Bundle):
    s = b.stats
    return (["TLS, modern only", "TLS 1.0/1.1 enabled", "Plain HTTP"],
            [s["ssl"] - s["weak_tls"], s["weak_tls"], s["plain"]],
            [BADGE["green"], BADGE["red"], BADGE["grey"]])


def _s_signatures(b: Bundle):
    rows = b.stats["signatures"][:PDF_CHART_POINTS]
    return ([n for n, _v in rows], [v for _n, v in rows],
            [BADGE["purple"]] * len(rows))


def _s_changes(b: Bundle):
    ch = svc.change_series(b.waf)
    return ch["labels"], ch["values"], [BADGE["accent"]]


def _s_readiness(b: Bundle):
    s = b.art_stats
    labels = [artsvc.STATE_LABELS[v] for v in artsvc.VERDICTS]
    values = [s["by_state"][v] for v in artsvc.VERDICTS]
    palette = {"ok": BADGE["green"], "borrowed": BADGE["amber"],
               "at-risk": BADGE["amber"], "blocked": BADGE["red"]}
    return labels, values, [palette.get(v, BADGE["grey"]) for v in artsvc.VERDICTS]


def _s_by_kind(b: Bundle):
    rows = [k for k in artsvc.by_kind(b.art)
            if k["needed"] or k["versions"] or k["orphan"] or k["library"]]
    return ([k["label"] for k in rows], [k["needed"] for k in rows],
            [BADGE["blue"]] * len(rows))


def _s_growth(b: Bundle):
    g = artsvc.growth_series(b.art)
    return g["labels"], g["values"], [BADGE["accent"]]


CHARTS: tuple[ChartSpec, ...] = (
    ChartSpec("posture", "Enforcement posture", "pie", "overview", _s_posture,
              note="one bucket per policy — the un-bucketed totals are in the "
                   "figures sheet"),
    ChartSpec("per_scope", "Server policies by device / ADOM", "bar",
              "overview", _s_per_scope),
    ChartSpec("coverage", "Protection coverage across the fleet", "bar",
              "overview", _s_coverage, unit="% of applicable policies",
              note="applicable, not total: a slot the profile does not HAVE "
                   "is not a slot switched off"),
    ChartSpec("crypto", "Transport security", "pie", "overview", _s_crypto),
    ChartSpec("signatures", "Signature policy in use", "bar", "overview",
              _s_signatures, note="disabled policies excluded"),
    ChartSpec("changes", "Configuration changes, last 30 days", "line",
              "overview", _s_changes, unit="snapshots minted",
              note="a row exists because the configuration CHANGED — a flat "
                   "zero is a quiet fleet, not a broken chart"),
    ChartSpec("readiness", "Artifact migration readiness", "pie", "artifacts",
              _s_readiness, unit="(scope, object) pairs"),
    ChartSpec("by_kind", "Artifacts needed by object type", "bar", "artifacts",
              _s_by_kind, unit="(scope, object) pairs",
              note="types with nothing at all are dropped: a bar of zeros for "
                   "an unused type reads as a gap"),
    ChartSpec("growth", "Artifact store growth", "line", "artifacts",
              _s_growth, unit="versions stored"),
)


def chart_rows(b: Bundle, keys: Sequence[str]) -> list[dict]:
    """Every selected chart as LONG rows — the numbers behind the pictures.

    This is what makes "export the charts" mean something in a CSV. A chart the
    reader cannot re-derive is a picture; a chart with its series attached is
    data. The PDF draws from the same :class:`ChartSpec`, so the drawing and
    the table cannot disagree.
    """
    out: list[dict] = []
    for spec in CHARTS:
        if spec.dataset not in keys:
            continue
        labels, values, _c = spec.series(b)
        for label, value in zip(labels, values):
            out.append({"chart": spec.title, "label": label,
                        "value": value, "unit": spec.unit})
    return out


# ---------------------------------------------------------------------------
# Dataset registry
# ---------------------------------------------------------------------------
class Dataset:
    __slots__ = ("key", "label", "sheet", "filename", "columns", "build",
                 "about", "needs")

    def __init__(self, key, label, sheet, filename, columns, build, about,
                 needs=""):
        self.key, self.label, self.sheet = key, label, sheet
        self.filename, self.columns, self.build = filename, columns, build
        self.about, self.needs = about, needs


_POLICY_COLUMNS = (
    ("scope", "Device / ADOM"), ("name", "Server policy"),
    ("posture_label", "Enforcement"), ("status", "Status"),
    ("service", "Service"), ("ssl_text", "TLS"),
    ("certificate", "Certificate"), ("vserver", "Virtual server"),
    ("pool", "Server pool"), ("wpp", "Web protection profile"),
    ("wpp_kind", "Profile type"), ("n_protections", "Protections on"),
    ("protection_list", "Protections"), ("signature_rule", "Signature policy"),
    ("deployment", "Deployment mode"), ("comment", "Comment"),
)

_PROFILE_COLUMNS = (
    ("scope", "Device / ADOM"), ("name", "Profile"), ("kind", "Type"),
    ("origin", "Origin"), ("used_by", "Policies using it"),
    ("n_filled", "Protections on"), ("n_applicable", "Slots available"),
    ("protection_list", "Protections"), ("orphan", "Orphan"),
    ("signature_rule", "Signature policy"), ("comment", "Comment"),
)

_COVERAGE_COLUMNS = (
    ("protection", "Protection"), ("group", "Group"),
    ("scope", "Device / ADOM"), ("on", "On"),
    ("applicable", "Applicable"), ("pct", "% of applicable"),
    ("verdict", "Verdict"),
)

_ARTIFACT_COLUMNS = (
    ("scope", "Device / ADOM"), ("label", "Object type"), ("name", "Object"),
    ("state_label", "State"), ("empty_flag", "Empty"),
    ("policies", "Policies naming it"), ("policy_list", "Which policies"),
    ("profiles", "Profiles naming it"),
    ("versions", "Versions held"), ("size", "Newest bytes"),
    ("source", "Origin"), ("sha", "Newest sha"),
    ("created_at", "First stored"),
    ("recoverable", "Recoverable from device"), ("remedy", "What to do"),
)

# Builder adapters. Every dataset builder has the SAME signature ``(bundle,
# selected keys)`` so ``_rows_for`` can be the single row-building path — the
# overview one is the reason the argument exists: its artifact half is only
# honest when the artifact universe was actually collected for this bundle.
def _ds_overview(b: Bundle, keys: Sequence[str]) -> list[dict]:
    rows = _summary(b)
    if "artifacts" in keys:
        rows += _artifact_summary(b)
    return rows


def _ds_policies(b: Bundle, keys: Sequence[str]) -> list[dict]:
    return _policies(b)


def _ds_profiles(b: Bundle, keys: Sequence[str]) -> list[dict]:
    return _profiles(b)


def _ds_coverage(b: Bundle, keys: Sequence[str]) -> list[dict]:
    return _coverage(b)


def _ds_artifacts(b: Bundle, keys: Sequence[str]) -> list[dict]:
    return _artifacts(b)


def _ds_exceptions(b: Bundle, keys: Sequence[str]) -> list[dict]:
    return b.exceptions


DATASETS: tuple[Dataset, ...] = (
    Dataset("overview", "Overview figures & charts", "Fleet figures",
            "fleet-figures.csv", SUMMARY_COLUMNS, _ds_overview,
            "Every headline figure on /waf/, and the series behind its six "
            "charts. Computed from the source-of-truth snapshots; contacts no "
            "appliance."),
    Dataset("policies", "Server policies", "Server policies",
            "server-policies.csv", _POLICY_COLUMNS, _ds_policies,
            "One row per server policy in every scope that reported a "
            "snapshot."),
    Dataset("profiles", "Web protection profiles", "Protection profiles",
            "protection-profiles.csv", _PROFILE_COLUMNS, _ds_profiles,
            "One row per web protection profile, with how many policies bind "
            "it and how many of its available slots are switched on."),
    Dataset("coverage", "Protection coverage", "Coverage",
            "protection-coverage.csv", _COVERAGE_COLUMNS, _ds_coverage,
            "Protection x scope in long form. 'Applicable' is carried beside "
            "'On' because a slot the profile does NOT have is not a slot that "
            "is switched off."),
    Dataset("artifacts", "Artifacts (file-backed objects)", "Artifacts",
            "artifacts.csv", _ARTIFACT_COLUMNS, _ds_artifacts,
            "What the estate references, what SATOM holds, and therefore what "
            "could not be migrated today. Read from the artifact index, not "
            "from the devices."),
    Dataset("exceptions", "Exceptions with their profiles", "Exceptions",
            "exceptions.csv", EXCEPTION_COLUMNS, _ds_exceptions,
            "DESIRED STATE authored in SATOM, joined to the profile it names "
            "and the policies that profile serves. SATOM does not record "
            "whether a carve-out was ever pushed to a device, so no row here "
            "claims it was."),
)

DATASET_KEYS = tuple(d.key for d in DATASETS)
_BY_KEY = {d.key: d for d in DATASETS}


def _rows_for(ds: Dataset, b: Bundle, keys: Sequence[str]) -> list[dict]:
    """The ONE place a dataset's rows come from.

    Every writer (CSV, workbook, PDF) and the manifest's own row counts call
    this. A second row-building path is how a manifest comes to advertise a
    count the file next to it does not contain.
    """
    return ds.build(b, keys)


# ---------------------------------------------------------------------------
# Provenance — ONE author for the four facts every artefact must carry
# ---------------------------------------------------------------------------
def provenance(b: Bundle, keys: Sequence[str], formats: Sequence[str],
               *, author: str = "", counts: dict | None = None) -> list[str]:
    """The block that goes at the top of the manifest, the workbook and the PDF."""
    devices = b.waf["devices"]
    reporting = [d for d in devices if not d["missing"]]
    stale = [d for d in devices if d["stale"]]
    missing = [d for d in devices if d["missing"]]

    lines = [
        "SATOM — Fleet WAF export",
        "=" * 64,
        "Generated       : %s UTC" % b.now.isoformat(timespec="seconds"),
        "Generated by    : %s" % (author or "unknown"),
        "Contents        : %s" % ", ".join(
            _BY_KEY[k].label for k in DATASET_KEYS if k in keys),
        "Formats         : %s" % ", ".join(formats),
        "",
        "SCOPE — this is the denominator of every figure in this bundle",
        "-" * 64,
        "Device/ADOM scopes visible to the exporting console : %d" % len(devices),
        "  of which reported a configuration snapshot        : %d" % len(reporting),
        "  of which are STALE (snapshot older than %2dh)      : %d"
        % (svc.STALE_AFTER_HOURS, len(stale)),
        "  of which were NEVER harvested                     : %d" % len(missing),
    ]
    if stale:
        lines.append("Stale scopes    : " + ", ".join(d["scope"] for d in stale))
    if missing:
        lines.append("Never harvested : " + ", ".join(d["scope"] for d in missing))
        lines.append("                  ^ these contribute NOTHING to the figures.")
        lines.append("                    They are not devices with zero policies.")
    lines += [
        "",
        "WHAT THIS BUNDLE IS, AND IS NOT",
        "-" * 64,
        "* Configuration figures are read from the source-of-truth store, so",
        "  they are exactly as old as the last harvest of each scope. Nothing",
        "  here was read live from an appliance.",
        "* The bundle is the WHOLE visible fleet. Filters on the /waf/ pages",
        "  narrow the screen and the per-page CSV link; they do not narrow",
        "  this file.",
        "* Visibility is the exporting user's: a scope this console cannot see",
        "  is absent from every number above and below.",
    ]
    if "exceptions" in keys:
        lines += [
            "* Exceptions are DESIRED STATE authored in SATOM. There is no",
            "  record of whether any carve-out was pushed to a device, so no",
            "  row in that dataset claims it was deployed.",
        ]
    lines += ["", "CONTENTS", "-" * 64]
    for key in DATASET_KEYS:
        if key not in keys:
            continue
        ds = _BY_KEY[key]
        head = ds.label
        if counts and key in counts:
            head = "%s (%d rows)" % (ds.label, counts[key])
        lines.append("* " + head)
        lines += ["    " + chunk for chunk in _wrap(ds.about, 68)]
    return lines


def _wrap(text: str, width: int) -> list[str]:
    out, line = [], ""
    for word in text.split():
        if line and len(line) + 1 + len(word) > width:
            out.append(line)
            line = word
        else:
            line = (line + " " + word) if line else word
    if line:
        out.append(line)
    return out


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------
def _csv_bytes(columns, rows) -> bytes:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow([label for _k, label in columns])
    for row in rows:
        w.writerow([_cell(row.get(k, "")) for k, _l in columns])
    return buf.getvalue().encode("utf-8-sig")   # BOM: Excel opens UTF-8 CSV


def _cell(value) -> Any:
    if isinstance(value, (list, tuple)):
        return ", ".join(str(v) for v in value)
    if isinstance(value, bool):
        return "yes" if value else "no"
    return value


def _grid(columns, rows) -> list[list[Any]]:
    grid = [[label for _k, label in columns]]
    for row in rows:
        grid.append([_cell(row.get(k, "")) for k, _l in columns])
    return grid


def build_xlsx(b: Bundle, keys: Sequence[str], *, author: str = "",
               counts: dict | None = None) -> bytes:
    """One workbook. Sheet 1 is provenance, ALWAYS — before any data sheet.

    Not a courtesy: a workbook whose first sheet is 4 000 policies is a
    workbook whose reader never learns that two of the scopes never reported.
    """
    sheets: list[tuple[str, list[list[Any]]]] = [
        ("Scope & freshness",
         [[line] for line in provenance(b, keys, ["xlsx"], author=author,
                                        counts=counts)]
         + [[""], ["Per-scope detail"]]
         + _grid(SCOPE_COLUMNS, _scopes(b))),
    ]
    for ds in DATASETS:
        if ds.key not in keys:
            continue
        # Row 0 is the column header and nothing else: xlsx_writer bolds and
        # freezes it. A prose line above it would freeze the prose and leave
        # the real header scrolling away — the "about" text for every dataset
        # is on the Scope sheet, where the reader arrives first.
        sheets.append((ds.sheet, _grid(ds.columns, _rows_for(ds, b, keys))))
    series = chart_rows(b, keys)
    if series:
        sheets.append(("Chart series", _grid(CHART_COLUMNS, series)))
    return xlsx_writer.write_book(sheets)


def build_pdf(b: Bundle, keys: Sequence[str], *, author: str = "",
              counts: dict | None = None) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (HRFlowable, PageBreak, Paragraph,
                                    Preformatted, SimpleDocTemplate,
                                    Spacer)

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm,
        topMargin=15 * mm, bottomMargin=14 * mm,
        title="SATOM — Fleet WAF export", author=author or "SATOM")
    base = getSampleStyleSheet()
    accent = BADGE["accent"]
    h1 = ParagraphStyle("H1", parent=base["Title"], fontSize=20,
                        textColor=colors.HexColor("#1B1F26"), spaceAfter=2)
    h2 = ParagraphStyle("H2", parent=base["Heading2"], fontSize=13,
                        textColor=colors.HexColor("#1B1F26"),
                        spaceBefore=12, spaceAfter=4)
    body = ParagraphStyle("Body", parent=base["Normal"], fontSize=9,
                          textColor=colors.HexColor("#3D4550"), leading=12)
    small = ParagraphStyle("Small", parent=base["Normal"], fontSize=7.5,
                           textColor=colors.HexColor("#3D4550"), leading=10)
    mono = ParagraphStyle("Mono", parent=base["Normal"], fontSize=7.6,
                          fontName="Courier", leading=9.6,
                          textColor=colors.HexColor("#1B1F26"))
    cell = ParagraphStyle("Cell", parent=base["Normal"], fontSize=6.8, leading=8.4)

    story = [Paragraph("SATOM &mdash; Fleet WAF export", h1),
             Paragraph("Every FortiWeb this console can see, as of the last "
                       "harvest of each scope.", body),
             HRFlowable(width="100%", thickness=1.2,
                        color=colors.HexColor(accent)),
             Spacer(1, 6)]
    # Preformatted, not a Paragraph with &nbsp; padding. Both align the
    # block, but nbsp-joining emits every WORD as its own text literal, so
    # the page becomes unsearchable — in a reader, in grep, and in the
    # guard that is supposed to prove the page is there. That is exactly
    # how a mutation deleting this whole block survived: the phrase the
    # guard looked for also appears as a row LABEL in the figures table.
    for line in provenance(b, keys, ["pdf"], author=author, counts=counts):
        story.append(Preformatted(line, mono))
    story.append(PageBreak())

    avail = doc.width
    for ds in DATASETS:
        if ds.key not in keys:
            continue
        rows = _rows_for(ds, b, keys)
        story.append(Paragraph(pdf_kit.esc(ds.label), h2))
        story.append(Paragraph(pdf_kit.esc(ds.about), body))
        story.append(Spacer(1, 4))

        for spec in CHARTS:
            if spec.dataset != ds.key:
                continue
            labels, values, colours = spec.series(b)
            story.append(Paragraph(pdf_kit.esc(spec.title), body))
            story.append(pdf_kit.chart_flowable(
                {"labels": labels, "values": values}, spec.viz, avail,
                max_points=PDF_CHART_POINTS, colours=colours,
                palette=SERIES_PALETTE, accent=accent, accent2=BADGE["purple"]))
            foot = "%s · %d series points" % (spec.unit, len(values))
            if len(values) > PDF_CHART_POINTS:
                foot += " · first %d drawn" % PDF_CHART_POINTS
            if spec.note:
                foot += " · " + spec.note
            story.append(Paragraph(pdf_kit.esc(foot), small))
            story.append(Spacer(1, 8))

        if not rows:
            story.append(Paragraph("No rows.", small))
        else:
            story.append(pdf_kit.table_flowable(
                {"columns": [l for _k, l in ds.columns],
                 "rows": [[_cell(r.get(k, "")) for k, _l in ds.columns]
                          for r in rows]},
                avail, cell, max_rows=PDF_TABLE_ROWS, accent=accent,
                header_bg="#FDEDE8"))
            note = "%d rows" % len(rows)
            if len(rows) > PDF_TABLE_ROWS:
                # NEVER silent: a table that stops at 40 without saying so is
                # a table that claims the fleet has 40 of these.
                note += (" · first %d shown — the CSV and the workbook in this "
                         "ZIP hold all of them" % PDF_TABLE_ROWS)
            if len(ds.columns) > 10:
                note += " · first 10 columns shown"
            story.append(Paragraph(pdf_kit.esc(note), small))
        story.append(PageBreak())

    doc.build(story)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# The bundle
# ---------------------------------------------------------------------------
def filename_for(now: datetime) -> str:
    return "satom-waf-fleet-%s.zip" % now.strftime("%Y%m%d-%H%M%S")


def build_zip(*, keys: Sequence[str], formats: Sequence[str], user=None,
              author: str = "", now: datetime | None = None) -> tuple[bytes, str]:
    """Assemble the archive. Returns ``(bytes, filename)``.

    Raises ``ValueError`` when nothing was selected. A zero-byte-content ZIP
    downloads perfectly happily and reads as "there was nothing to export",
    which is a claim about the fleet rather than about the form.
    """
    keys = [k for k in DATASET_KEYS if k in set(keys)]
    formats = [f for f, _l in FORMATS if f in set(formats)]
    if not keys:
        raise ValueError("select at least one dataset to export")
    if not formats:
        raise ValueError("select at least one file format")

    b = Bundle(user=user, now=now)
    root = "satom-waf-fleet-%s" % b.now.strftime("%Y%m%d-%H%M%S")

    # Row counts come from the SAME builders the files are written from, so
    # the manifest cannot advertise a count the file does not contain.
    materialised = {ds.key: _rows_for(ds, b, keys)
                    for ds in DATASETS if ds.key in keys}
    counts = {k: len(v) for k, v in materialised.items()}

    buf = io.BytesIO()
    notes: list[str] = []
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        if "csv" in formats:
            for ds in DATASETS:
                if ds.key not in keys:
                    continue
                zf.writestr("%s/csv/%s" % (root, ds.filename),
                            _csv_bytes(ds.columns, materialised[ds.key]))
            # Always present, whatever was ticked: it is the denominator, and a
            # folder of data files with no scope file is a folder that cannot
            # be audited later.
            zf.writestr("%s/csv/scopes.csv" % root,
                        _csv_bytes(SCOPE_COLUMNS, _scopes(b)))
            series = chart_rows(b, keys)
            if series:
                zf.writestr("%s/csv/chart-series.csv" % root,
                            _csv_bytes(CHART_COLUMNS, series))

        if "xlsx" in formats:
            try:
                zf.writestr("%s/xlsx/satom-waf-fleet.xlsx" % root,
                            build_xlsx(b, keys, author=author, counts=counts))
            except ValueError as exc:
                # xlsx_writer refuses past MAX_ROWS rather than truncating. A
                # bundle that silently loses its workbook is worse than one
                # that says why, in the manifest the reader already opens.
                notes.append("Excel workbook OMITTED: %s" % exc)

        if "pdf" in formats:
            zf.writestr("%s/pdf/satom-waf-fleet.pdf" % root,
                        build_pdf(b, keys, author=author, counts=counts))

        lines = provenance(b, keys, formats, author=author, counts=counts)
        if notes:
            lines += ["", "NOTES", "-" * 64] + notes
        zf.writestr("%s/MANIFEST.txt" % root, "\n".join(lines) + "\n")

    return buf.getvalue(), filename_for(b.now)


__all__ = ["BADGE", "CHARTS", "DATASETS", "DATASET_KEYS", "FORMATS",
           "Bundle", "build_pdf", "build_xlsx", "build_zip", "chart_rows",
           "exception_rows", "provenance", "filename_for"]
