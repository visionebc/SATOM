"""Sync orchestration — populate the local cache (source of truth) from a device
and keep a git-backable per-device JSON backup.

Three triggers converge here: manual ⟳, scheduled (Automation → Actions), and
write-through after an approved edit. Live reads are read-only REST sweeps.

The per-device JSON backup lives at ``data/reports/<slug>/_config.json``
(human-readable "latest" view; ``satom-ha-datasync`` replicates it to the
standby like the rest of ``data/``). Versioning/history moved from git to the
local content-addressed store (``services.sot_store``) on 2026-08-05 — a git
repo receiving the whole fleet's snapshots hourly grows without bound at
scale. ``publish=True`` now pushes the store's blobs to the external backup
server instead of committing to git. Override the reports root with
``FORTINET_REPORTS_DIR`` (tests).
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime
from pathlib import Path


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _reports_dir() -> Path:
    # data/reports, NOT the repo-root reports/: data/ rides the existing
    # standby rsync and the backup bundles; a repo-root path would need its
    # own replication channel now that git no longer carries it. A compat
    # symlink reports/ -> data/reports covers external readers.
    d = Path(os.environ.get("FORTINET_REPORTS_DIR")
             or (_repo_root() / "data" / "reports"))
    d.mkdir(parents=True, exist_ok=True)
    return d


def slugify(name: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9_.-]+", "-", (name or "").strip()).strip("-")
    return s or "device"


def device_json_path(appliance) -> Path:
    d = _reports_dir() / slugify(getattr(appliance, "name", str(appliance)))
    d.mkdir(parents=True, exist_ok=True)
    return d / "_config.json"


def write_device_json(appliance, snapshot: dict) -> Path:
    """Atomic write of the per-device JSON backup."""
    p = device_json_path(appliance)
    tmp = p.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(snapshot, indent=2, default=str), encoding="utf-8")
    os.replace(tmp, p)
    return p


_SWEEP_ABORT_AFTER = 8


def snapshot_from_device(appliance, *, timeout: float = 20.0) -> dict:
    """Live, read-only sweep of every top-level cmdb section -> snapshot dict."""
    from .rediscovery import sweep_plan
    from ..clients.fortiweb import FortiWebClient

    client = FortiWebClient(appliance, timeout=timeout)
    plan = sweep_plan()
    sections: dict = {}
    total = 0
    errors: list[dict] = []
    answered: dict[str, str] = {}   # every table that answered, empty ones too
    consecutive = 0
    for ep in plan:
        # list_with_error surfaces device-level refusals (license lock -20010,
        # auth, dead host) while the benign -20001/-3 (endpoint absent on this
        # firmware) still reads as empty — the registry is a superset.
        rows, err = client.list_with_error(ep["urn"])
        if err:
            errors.append({"endpoint": ep["name"], "error": str(err)[:160]})
            consecutive += 1
            if consecutive >= _SWEEP_ABORT_AFTER:
                # A dead/locked box fails EVERY endpoint; keep hammering it and a
                # ~470-endpoint sweep burns 20+ minutes to learn nothing.
                errors.append({"endpoint": "_sweep",
                               "error": f"aborted after {consecutive} consecutive "
                                        "device-level failures"})
                break
            continue
        consecutive = 0
        answered[ep["name"]] = ep["section"]
        rows = [r for r in rows if isinstance(r, dict)]
        if rows:
            sections.setdefault(ep["section"], {})[ep["name"]] = rows
            total += len(rows)
    return {
        "device": appliance.name, "appliance_id": appliance.id,
        "generated_at": datetime.utcnow().isoformat(), "total_objects": total,
        "section_count": len(sections), "sections": sections, "errors": errors,
        "answered": answered,
    }


def snapshot_from_adc(appliance, *, timeout: float = 20.0) -> dict:
    """Live, read-only sweep of a FortiADC appliance -> snapshot dict.

    The ADC counterpart of :func:`snapshot_from_device`: it reuses the ADC
    discovery plan (``services.adc_ops.discovery_plan`` — every enabled
    ``product='fortiadc'`` registry endpoint, child tables excluded) and a single
    authenticated ``FortiADCClient`` fetcher, and emits the SAME snapshot shape so
    ``device_store.ingest_snapshot`` and the ``reports/<slug>/_config.json`` writer
    are shared verbatim. Must run in an app context (the registry is DB-first)."""
    from ..registry import loader
    from . import adc_ops

    plan = adc_ops.discovery_plan(loader.version_of(appliance))
    fetch = adc_ops.make_fetcher(appliance)
    sections: dict = {}
    total = 0
    errors: list[dict] = []
    answered: dict[str, str] = {}   # every table that answered, empty ones too
    consecutive = 0
    for ep in plan:
        try:
            rows = fetch(ep)
        except Exception as exc:  # noqa: BLE001 — device-level refusal / dead host
            errors.append({"endpoint": ep["name"], "error": str(exc)[:160]})
            consecutive += 1
            if consecutive >= _SWEEP_ABORT_AFTER:
                # A dead/locked box fails EVERY endpoint; don't burn the whole plan.
                errors.append({"endpoint": "_sweep",
                               "error": f"aborted after {consecutive} consecutive "
                                        "device-level failures"})
                break
            continue
        consecutive = 0
        answered[ep["name"]] = ep["section"]
        rows = [r for r in rows if isinstance(r, dict)]
        if rows:
            sections.setdefault(ep["section"], {})[ep["name"]] = rows
            total += len(rows)
    return {
        "device": appliance.name, "appliance_id": appliance.id,
        "generated_at": datetime.utcnow().isoformat(), "total_objects": total,
        "section_count": len(sections), "sections": sections, "errors": errors,
        "answered": answered,
    }


def _menu_sections(menu) -> dict[str, str]:
    """``{registry name: menu group}`` of a FAZ/FAC menu — the sections a
    sweep files its tables under (unmapped ones land in "Other")."""
    section_of: dict[str, str] = {}
    try:
        for g in menu():
            for item in g.items:
                for logical, _label in item.logicals:
                    section_of.setdefault(logical, g.label)
    except Exception:  # noqa: BLE001 — the menu is cosmetic for the sweep
        pass
    return section_of


# FortiAnalyzer registry endpoints that are OPERATIONAL data (live alerts,
# log rates, clocks, task queues) — excluded from the config SoT harvest so
# reports/<faz>/_config.json only changes when the CONFIG changes (no hourly
# git churn from moving timestamps/counters). ``report_generated`` (reports
# the box produced, which also needs ``state`` + ``time-range``: every sync
# logged "-32002 Missing state") and ``logview_logfiles`` (log-file state)
# are outputs of the box, not its configuration.
_FAZ_SOT_EXCLUDE = {
    "sys_status", "sys_ha_status", "task_task",
    "eventmgmt_alerts", "eventmgmt_alertlogs", "incidentmgmt_incidents",
    "logview_logstats", "logview_logfields", "storage_info",
    "report_generated", "logview_logfiles",
}


def snapshot_from_faz(appliance, *, timeout: float = 20.0) -> dict:
    """Live, read-only sweep of a FortiAnalyzer unit -> snapshot dict.

    The FAZ counterpart of :func:`snapshot_from_adc`: every
    ``product='fortianalyzer'`` endpoint of the box's build
    (``loader.registry_for``) except the operational ones
    (``_FAZ_SOT_EXCLUDE``), fetched over one authenticated JSON-RPC session,
    emitting the SAME snapshot shape so ``device_store.ingest_snapshot`` + the
    ``reports/<slug>/_config.json`` writer + git publish are shared verbatim.
    Sections come from the FAZ menu groups; unmapped endpoints land in
    "Other". Must run in an app context (the registry is DB-first).

    Rows go through the FortiAnalyzer secret scrub of the section pages
    (``gui_products`` FortiAnalyzerAdapter): JSON-RPC answers every secret as
    ``["ENC", "<salted blob>"]``. Kept, they put device secrets in
    ``_config.json`` and every SoT blob, and the salt changes on each read, so
    an unchanged faz02 minted a new version every hour."""
    from ..clients.fortianalyzer import FortiAnalyzerClient
    from ..registry import loader
    from . import faz_menu
    from .gui_products import FORTIANALYZER, adapter
    scrub = adapter(FORTIANALYZER).scrub

    # The map of THIS box's build (loader.registry_for): a name its build
    # measured absent is not swept, one it serves after the baseline disabled
    # it still is.
    reg = loader.registry_for("fortianalyzer", loader.version_of(appliance))
    section_of = _menu_sections(faz_menu.menu)

    client = FortiAnalyzerClient(appliance, timeout=timeout)
    sections: dict = {}
    shapes: dict[str, str] = {}   # every answered table, empty ones too (Naming)
    total = 0
    errors: list[dict] = []
    answered: dict[str, str] = {}   # every table that answered, empty ones too
    consecutive = 0
    for name in sorted(reg):
        if name in _FAZ_SOT_EXCLUDE:
            continue
        rows, err, shape = client.list_with_shape(name)
        if shape:
            shapes[name] = shape
        if err:
            errors.append({"endpoint": name, "error": str(err)[:160]})
            consecutive += 1
            if consecutive >= _SWEEP_ABORT_AFTER:
                # A dead/locked box fails EVERY endpoint; don't burn the plan.
                errors.append({"endpoint": "_sweep",
                               "error": f"aborted after {consecutive} consecutive "
                                        "device-level failures"})
                break
            continue
        consecutive = 0
        answered[name] = section_of.get(name, "Other")
        rows = [scrub(r) for r in rows if isinstance(r, dict)]
        if rows:
            sections.setdefault(section_of.get(name, "Other"), {})[name] = rows
            total += len(rows)
    try:
        client.logout()
    except Exception:  # noqa: BLE001 — best-effort session hygiene
        pass
    return {
        "device": appliance.name, "appliance_id": appliance.id,
        "generated_at": datetime.utcnow().isoformat(), "total_objects": total,
        "section_count": len(sections), "sections": sections, "errors": errors,
        "answered": answered,
        "shapes": shapes,
    }


# Operational endpoints — EXCLUDED from the configuration snapshot on purpose.
# Every one of them changes between two consecutive reads of an idle unit
# (CPU/memory percentages, SMS and token quotas, the pending SCEP queue), so
# harvesting them would make the content hash differ every hour and record pure
# churn as a configuration change — defeating the dedupe that keeps the SoT
# store small. Same reasoning as _FAZ_SOT_EXCLUDE.
_FAC_SOT_EXCLUDE = {
    "system_info", "token_fortiguard_messages", "token_ftm_licenses",
    "cert_scep_requests",
}

# FortiAuthenticator resources that answer GET with 405: POST-only actions
# (authenticate, push a token, upgrade...), measured on fac01 8.0.3 build0099
# (2026-10-26) when the 8.0.3 baseline was promoted to the 52 measured names.
# Not configuration, so the sweep does not ask and Naming does not list them;
# a 405 from a resource NOT listed here (a later build) is skipped the same way.
_FAC_POST_ONLY = frozenset({
    "auth", "emergencytoken", "idpsessiondata", "licensing", "localapiadmin",
    "offlinehotpupdate", "offlineotp", "realmauth", "ssoauth", "system", "upgrade",
})


def snapshot_from_fac(appliance, *, timeout: float = 20.0) -> dict:
    """Live, read-only sweep of a FortiAuthenticator unit -> snapshot dict.

    The FAC counterpart of :func:`snapshot_from_faz`: every
    ``product='fortiauthenticator'`` endpoint of the box's build
    (``loader.registry_for``) except the operational ones
    (``_FAC_SOT_EXCLUDE``), emitting the SAME snapshot shape so
    ``device_store.ingest_snapshot`` + the ``reports/<slug>/_config.json``
    writer + the SoT store are shared verbatim. Sections come from the FAC menu
    groups; unmapped endpoints land in "Other".

    Secrets cannot leak through here: a canary round-trip on 2026-08-05
    confirmed the device omits ``radiusclients.secret`` and
    ``localusers.password`` from every GET payload. That is a property of the
    device, so it is re-verified by ``tests/test_fac_sot.py`` rather than
    assumed forever.

    Must run in an app context (the registry is DB-first)."""
    from ..clients.fortiauthenticator import FortiAuthenticatorClient
    from ..registry import loader
    from . import fac_menu

    # Per build, as for FortiAnalyzer above.
    reg = loader.registry_for("fortiauthenticator", loader.version_of(appliance))
    section_of = _menu_sections(fac_menu.visible_menu)

    client = FortiAuthenticatorClient(appliance, timeout=timeout)
    sections: dict = {}
    shapes: dict[str, str] = {}   # every answered table, empty ones too (Naming)
    total = 0
    errors: list[dict] = []
    answered: dict[str, str] = {}   # every table that answered, empty ones too
    consecutive = 0
    for name in sorted(reg):
        if name in _FAC_SOT_EXCLUDE or name in _FAC_POST_ONLY:
            continue
        rows, err, shape = client.list_with_shape(name)
        if shape:
            shapes[name] = shape
        if err and str(err).startswith("405"):
            # Served, not readable: a POST-only action resource (auth, system,
            # upgrade, ... -- 11 of the 52 on 8.0.3, measured on fac01). It is
            # neither configuration nor a failure.
            continue
        if err:
            errors.append({"endpoint": name, "error": str(err)[:160]})
            consecutive += 1
            if consecutive >= _SWEEP_ABORT_AFTER:
                # A dead box or a revoked API key fails EVERY endpoint; don't
                # burn the plan hammering it.
                errors.append({"endpoint": "_sweep",
                               "error": f"aborted after {consecutive} consecutive "
                                        "device-level failures"})
                break
            continue
        consecutive = 0
        answered[name] = section_of.get(name, "Other")
        rows = [r for r in rows if isinstance(r, dict)]
        if rows:
            sections.setdefault(section_of.get(name, "Other"), {})[name] = rows
            total += len(rows)
    # No logout: FortiAuthenticator authenticates each request with the API key
    # (HTTP Basic), so there is no session to release.
    if consecutive < _SWEEP_ABORT_AFTER:
        total += _fac_beyond_rest(appliance, sections, answered, errors, shapes)
    return {
        "device": appliance.name, "appliance_id": appliance.id,
        "generated_at": datetime.utcnow().isoformat(), "total_objects": total,
        "section_count": len(sections), "sections": sections, "errors": errors,
        "answered": answered,
        "shapes": shapes,
    }


#: Wall-clock budget of the GUI part of one FortiAuthenticator sweep.
FAC_GUI_BUDGET_S = 240


def fac_beyond_rest_endpoints(appliance) -> dict[str, str]:
    """``{endpoint: section}`` of every view of the device's build that the
    REST API does not serve: ``cli:<object>`` (5 on 8.0.3) and
    ``gui:/<path>/`` (the GUI-only pages: 72 of 93 on 8.0.3). Taken from the
    GUI layouts SATOM holds for that build -- the pages the harvester crawl
    measured, never a guessed path. Sections are the layout's menu group."""
    from . import gui_pages, gui_store
    product = "fortiauthenticator"
    fw = gui_store.firmware_of(appliance)
    out: dict[str, str] = {}
    try:
        entries = gui_pages.entries(fw, product)
    except Exception:  # noqa: BLE001 — no layouts on this node: nothing beyond REST
        return out
    for e in entries:
        tpl, _m = gui_pages.template(e["page"], fw, product)
        if not tpl:
            continue
        section = str((tpl.get("menu_path") or ["Other"])[0] or "Other")
        eps = [v.get("endpoint") for v in tpl.get("views") or [] if isinstance(v, dict)]
        eps.append(tpl.get("endpoint"))
        eps += [d.get("endpoint") for d in (tpl.get("dialogs") or {}).values()
                if isinstance(d, dict)]
        for ep in eps:
            if not isinstance(ep, str) or "<" in ep:
                continue
            if ep.startswith("cli:") or (ep.startswith("gui:/") and ep.endswith("/")):
                out.setdefault(ep, section)
    return out


def _fac_beyond_rest(appliance, sections: dict, answered: dict, errors: list,
                     shapes: dict) -> int:
    """Sweep what FortiAuthenticator serves outside its REST API: the CLI-only
    objects (``show full-configuration`` over SSH) and the GUI-only pages
    (``clients.fortiauthenticator_gui``). Both read-only; secrets dropped by
    both readers. Returns the objects added. A GUI that refuses the login is
    one error per GUI endpoint (coverage says ``failed``), never a guess."""
    import time
    from ..clients.fortiauthenticator_gui import FacGuiError, FacGuiReader
    from .gui_products import FortiAuthenticatorAdapter
    eps = fac_beyond_rest_endpoints(appliance)
    added = 0
    ad = FortiAuthenticatorAdapter()
    for ep, section in sorted(eps.items()):
        if not ep.startswith("cli:"):
            continue
        try:
            rows, err = ad.cli_rows(appliance, ep)
        except Exception as exc:  # noqa: BLE001 — one object never sinks the sweep
            rows, err = [], f"{type(exc).__name__}: {exc}"
        if err:
            errors.append({"endpoint": ep, "error": str(err)[:160]})
            continue
        answered[ep] = section
        rows = [r for r in rows if isinstance(r, dict)]
        shapes[ep] = "table" if any("_edit" in r for r in rows) else "singleton"
        if rows:
            sections.setdefault(section, {})[ep] = rows
            added += len(rows)
    gui = {ep: s for ep, s in eps.items() if ep.startswith("gui:/")}
    if not gui:
        return added
    if not getattr(appliance, "has_ssh_password", False) and not getattr(appliance, "ssh_password_enc", None):
        for ep in sorted(gui):
            errors.append({"endpoint": ep, "error": "no GUI login configured "
                           "(set the CLI / GUI admin password on the appliance)"})
        return added
    deadline = time.monotonic() + FAC_GUI_BUDGET_S
    paths = {ep[len("gui:"):]: ep for ep in gui}
    try:
        with FacGuiReader(appliance, allowed=paths) as rd:
            for path, ep in sorted(paths.items()):
                if time.monotonic() > deadline:
                    errors.append({"endpoint": ep, "error": "GUI budget exhausted "
                                   f"({FAC_GUI_BUDGET_S} s): not read this sweep"})
                    continue
                try:
                    got = rd.read_page(path, deadline=deadline)
                except FacGuiError as exc:
                    errors.append({"endpoint": ep, "error": str(exc)[:160]})
                    continue
                if got["truncated"]:
                    errors.append({"endpoint": ep, "error": "truncated: the change "
                                   f"forms of {got['total']} objects did not all fit "
                                   "in this sweep (list columns kept for the rest)"})
                answered[ep] = gui[ep]
                shapes[ep] = "table" if got["kind"] == "list" else "singleton"
                if got["rows"]:
                    sections.setdefault(gui[ep], {})[ep] = got["rows"]
                    added += len(got["rows"])
    except FacGuiError as exc:
        for ep in sorted(gui):
            if ep not in answered:
                errors.append({"endpoint": ep, "error": str(exc)[:160]})
    except Exception as exc:  # noqa: BLE001 — transport: the REST half stands
        for ep in sorted(gui):
            if ep not in answered:
                errors.append({"endpoint": ep, "error": f"{type(exc).__name__}: {exc}"[:160]})
    return added


def snapshot_from_fgt(appliance, *, timeout: float = 20.0) -> dict:
    """Live, read-only sweep of a FortiGate -> snapshot dict.

    The FortiGate counterpart of :func:`snapshot_from_fac`: every cmdb table
    the FortiGate ADOM menu reads (``services.fgt_menu``), at the path the
    endpoint registry resolves for THIS box's build (``views.fgt.resolve_tab``
    — a table the build does not serve is reported, never read at a guessed
    path). Rows go through the same secret scrub as the section pages
    (``views.fgt.scrub``): an ``ENC`` value or a password field never reaches
    the cache, the JSON backup or the SoT store. Single-instance settings
    tables are kept as a one-row list so the snapshot shape stays the shared
    one. Sections come from the menu groups; tables are keyed by their
    registry name. Before this sweep existed a FortiGate fell through to the
    FortiWeb sweep, failed every endpoint and never had a JSON backup."""
    from ..clients.fortigate import FortiGateClient
    from ..registry import loader
    from ..views.fgt import resolve_tab, scrub
    from . import fgt_menu

    client = FortiGateClient(appliance, timeout=timeout)
    sections: dict = {}
    total = 0
    errors: list[dict] = []
    answered: dict[str, str] = {}   # every table that answered, empty ones too
    consecutive = 0
    seen: set[str] = set()
    paths: dict[str, str] = {}      # table name -> cmdb path, for the CLI merge
    for g in fgt_menu.visible_menu():
        for item in g.items:
            for path, _label in item.tabs:
                if path in seen:
                    continue
                seen.add(path)
                name = loader.fgt_logical(path)
                read_path, err = resolve_tab(appliance, path)
                if err:
                    # the registry said no: the device was never asked, so
                    # this is not a device-level failure
                    errors.append({"endpoint": name, "error": str(err)[:160]})
                    continue
                results, err = client.cmdb(read_path, with_meta=1)
                if err:
                    errors.append({"endpoint": name, "error": str(err)[:160]})
                    consecutive += 1
                    if consecutive >= _SWEEP_ABORT_AFTER:
                        errors.append({"endpoint": "_sweep",
                                       "error": f"aborted after {consecutive} consecutive "
                                                "device-level failures"})
                        break
                    continue
                consecutive = 0
                answered[name] = g.label
                paths[name] = path
                if isinstance(results, dict):
                    rows = [scrub(results)]
                else:
                    rows = [scrub(r) for r in (results or []) if isinstance(r, dict)]
                if rows:
                    sections.setdefault(g.label, {})[name] = rows
                    total += len(rows)
            if consecutive >= _SWEEP_ABORT_AFTER:
                break
        if consecutive >= _SWEEP_ABORT_AFTER:
            break
    # What the REST GET itself returned, BEFORE any CLI field is merged in:
    # the API library learns the build's REST fields from it (persist_snapshot
    # ingests it, then drops it -- it is never part of the JSON or the SoT).
    library = {"firmware": str(getattr(appliance, "firmware", "") or ""),
               "endpoint_status": {}, "sections": {"rest": {}}}
    for label, tables in sections.items():
        for name, rows in tables.items():
            path = paths.get(name)
            if path:
                library["endpoint_status"][path] = {
                    "urn": "/api/v2/cmdb/" + path, "section": label,
                    "verdict": "ok", "rows": len(rows)}
                library["sections"]["rest"][path] = [dict(r) for r in rows]
    if consecutive < _SWEEP_ABORT_AFTER and sections:
        cli_tables: dict = {}
        fgt_merge_cli_only(appliance, sections, paths, errors, scrub=scrub,
                           cli_tables=cli_tables)
        for ep, rows in sorted(cli_tables.items()):
            answered[ep] = "CLI"
            sections.setdefault("CLI", {})[ep] = rows
            total += len(rows)
    return {
        "device": appliance.name, "appliance_id": appliance.id,
        "generated_at": datetime.utcnow().isoformat(), "total_objects": total,
        "section_count": len(sections), "sections": sections, "errors": errors,
        "_library": library,
        "answered": answered,
    }


_ENC_VALUE = re.compile(r"^(?:ENC|SH2)\s")


def normalise_vdom_chains(rows: dict, vdom: str | None) -> dict:
    """``show full-configuration`` chains of a multi-VDOM FortiGate without
    their wrapper: ``config global`` blocks lose it, the blocks of *vdom*
    (``root`` when unset) lose ``config vdom / edit <vdom>``, other VDOMs are
    dropped. A single-VDOM box (``vdom=0`` in the header) has neither wrapper
    and passes through unchanged."""
    want = (vdom or "root").strip() or "root"
    out: dict = {}
    for chain, lines in rows.items():
        if chain and chain[0] == ("global", None):
            chain = chain[1:]
        elif chain and chain[0][0] == "vdom":
            if chain[0][1] != want:
                continue
            chain = chain[1:]
        if chain:
            out.setdefault(chain, lines)
    return out


def fgt_merge_cli_only(appliance, sections: dict, paths: dict, errors: list, *,
                       scrub=lambda r: r, text: str | None = None,
                       cli_tables: dict | None = None) -> int:
    """Add the fields only the CLI serves to the REST rows of a FortiGate sweep.

    FortiGate 8.0.1 (fgt02) has 166 such fields in 76 tables -- the API
    library's ``cli_only`` / ``hidden`` channels of the build. The REST sweep
    never saw them, so the cache, the JSON backup and the SoT store did not
    hold them and the "Not in GUI, but in CLI" sections read them live. ONE
    read-only ``show full-configuration`` (1.4 MB in 1.8 s on fgt02) is parsed
    once, and each table's CLI-only fields are merged into its REST rows by
    the table key (``edit <key>``); a singleton's into its one row. Secrets
    (``cli_writer.is_secret``, ``ENC`` values) are never merged, and every
    merged row goes through the sweep's own scrub. Returns the fields merged.

    *text*: an already-read dump (tests). Best effort: the REST rows stand on
    their own, a CLI failure is one ``errors`` entry (``cli:full-configuration``)."""
    from ..registry import loader
    from . import api_library, cli_writer
    try:
        channels = (api_library.channels_at("fortigate", loader.version_of(appliance))
                    .get("endpoints") or {})
    except Exception as exc:  # noqa: BLE001 — no library for the build: nothing to merge
        errors.append({"endpoint": "cli:full-configuration",
                       "error": f"API library unavailable: {exc}"[:160]})
        return 0
    wanted: dict[str, dict] = {}            # table name -> {rest field: cli field}
    for name, path in paths.items():
        fields = (channels.get(path) or {}).get("fields") or {}
        cli = {f: str((d.get("attrs") or {}).get("cli_name") or f)
               for f, d in fields.items()
               if (d or {}).get("channel") in ("cli_only", "hidden")
               and not cli_writer.is_secret(f, (d or {}).get("attrs"))}
        if cli:
            wanted[name] = cli
    if not wanted and cli_tables is None:
        return 0
    if text is None:
        try:
            w = cli_writer.CliWriter(appliance, audit=False)
            sess = w._reader_factory()
            sess.connect()
            try:
                text = sess.run_readonly("show full-configuration")
            finally:
                try:
                    sess.close()
                except Exception:  # noqa: BLE001
                    pass
        except Exception as exc:  # noqa: BLE001 — SSH unreachable: REST rows stand
            errors.append({"endpoint": "cli:full-configuration",
                           "error": f"{type(exc).__name__}: {exc}"[:160]})
            return 0
    chains = normalise_vdom_chains(cli_writer.show_rows(text or ""),
                                   getattr(appliance, "vdom", None))
    if cli_tables is not None:
        cli_tables.update(_fgt_cli_only_tables(appliance, chains, paths))
    merged = 0
    for label, tables in sections.items():
        for name, rows in tables.items():
            cli = wanted.get(name)
            if not cli:
                continue
            try:
                split = cli_writer.split_payload(appliance, paths[name], {})
            except Exception as exc:  # noqa: BLE001
                errors.append({"endpoint": name, "error": f"CLI path: {exc}"[:160]})
                continue
            obj = split.get("object") or {}
            cli_path = " ".join(str(obj.get("cli_path") or "").split())
            mkey_field = str(obj.get("mkey") or "")
            if not cli_path or obj.get("parent"):
                continue
            singleton = obj.get("kind") == cli_writer.cli_schema.KIND_SINGLETON
            for i, row in enumerate(rows):
                key = None if singleton else str(row.get(mkey_field, "")) if mkey_field else None
                if not singleton and not key:
                    continue
                lines = chains.get(((cli_path, key),))
                if lines is None:
                    continue
                vals = cli_writer.row_values(lines, cli_path)["values"]
                add = {}
                for rest_name, cli_name in cli.items():
                    if rest_name in row:
                        continue
                    # the library spells a CLI-only field as the CLI tree
                    # names it (bgp_debug_flags) while `show` prints
                    # bgp-debug-flags: either spelling is the same field
                    got = next((c for c in (cli_name, cli_name.replace("_", "-"),
                                            cli_name.replace("-", "_")) if c in vals), None)
                    if got is None:
                        continue
                    v = vals[got]
                    if isinstance(v, str) and _ENC_VALUE.search(v.strip()):
                        continue
                    add[rest_name] = v
                if add:
                    rows[i] = scrub({**row, **add})
                    merged += len(add)
    return merged


_PEM_PRIVATE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY", re.I)


def _fgt_cli_value_ok(name: str, value) -> bool:
    from . import cli_writer
    if cli_writer.is_secret(name):
        return False
    if isinstance(value, str) and (_ENC_VALUE.search(value.strip()) or _PEM_PRIVATE.search(value)):
        return False
    return True


def _fgt_cli_only_tables(appliance, chains: dict, paths: dict) -> dict[str, list]:
    """``{"cli:<config path>": rows}`` of every top-level configuration table
    in the dump that the REST sweep does not read (the sweep reads the 43
    tables of SATOM's FortiGate menu; ``show full-configuration`` on fgt02
    prints 676). A row is ``{field: value}`` plus ``_edit`` (its CLI key) for a
    table; a nested ``config`` block is a list under its words. Secrets are
    dropped exactly as in the merge."""
    from . import cli_writer
    covered = set()
    for _name, path in paths.items():
        try:
            o = (cli_writer.split_payload(appliance, path, {}).get("object") or {})
        except Exception:  # noqa: BLE001
            continue
        covered.add(" ".join(str(o.get("cli_path") or "").split()))
    nodes: dict = {}
    for chain, lines in chains.items():
        words, key = chain[-1]
        vals = cli_writer.row_values(lines, words)["values"]
        row = {k: v for k, v in vals.items() if _fgt_cli_value_ok(k, v)}
        if key is not None:
            row["_edit"] = key
        elif not row:
            # a table's own ``config <words>`` line (its rows are the chains
            # with an edit key below it), or an empty block: not a row
            nodes[chain] = None
            continue
        nodes[chain] = row
    out: dict[str, list] = {}
    for chain in sorted(nodes, key=len):
        row = nodes[chain]
        if row is None:
            continue
        if len(chain) == 1:
            path = chain[0][0]
            if path in covered:
                continue
            out.setdefault("cli:" + path, []).append(row)
            continue
        # the row (or settings block) the nested ``config`` sits in
        parent = nodes.get(chain[:-1])
        if isinstance(parent, dict):
            parent.setdefault(chain[-1][0], []).append(row)
    return out


def sweep_tables(product: str, appliances=()) -> dict[str, str]:
    """``{table: section}`` the configuration sweep of *product* reads — the
    object types a device's tree can hold (Naming lists them all, including
    the ones no device has an object of yet). Mirrors the ``snapshot_from_*``
    plans; FortiAnalyzer and FortiAuthenticator sweep per build, so their
    tables are the union over *appliances*. Must run in an app context."""
    out: dict[str, str] = {}
    if product == "fortiweb":
        from .rediscovery import sweep_plan
        for ep in sweep_plan():
            out.setdefault(ep["name"], ep["section"])
    elif product == "fortiadc":
        from . import adc_ops
        for ep in adc_ops.discovery_plan():
            out.setdefault(ep["name"], ep["section"])
    elif product == "fortigate":
        from ..registry import loader
        from . import fgt_menu
        for g in fgt_menu.visible_menu():
            for item in g.items:
                for path, _label in item.tabs:
                    out.setdefault(loader.fgt_logical(path), g.label)
    elif product in ("fortianalyzer", "fortiauthenticator"):
        from ..registry import loader
        from . import fac_menu, faz_menu
        faz = product == "fortianalyzer"
        section_of = _menu_sections(faz_menu.menu if faz else fac_menu.visible_menu)
        exclude = _FAZ_SOT_EXCLUDE if faz else (_FAC_SOT_EXCLUDE | _FAC_POST_ONLY)
        for a in appliances:
            for name in loader.registry_for(product, loader.version_of(a)):
                if name not in exclude:
                    out.setdefault(name, section_of.get(name, "Other"))
            if not faz:
                for ep, section in fac_beyond_rest_endpoints(a).items():
                    out.setdefault(ep, section)
    return out


def table_kinds(product: str, appliances, tables, trees=()) -> dict[str, str]:
    """``{table: "table" | "singleton"}`` for the *tables* (registry names)
    whose shape was measured: by the API library on the builds of
    *appliances*, and by the sweep itself -- the FortiAnalyzer and
    FortiAuthenticator sweeps record what each table answered, empty ones
    included, in the snapshot's ``shapes`` (*trees*).

    The name is matched by its URN on each build and by itself, both folded
    (:func:`api_library.object_kind_key`). A table any measure saw as a list
    is a ``table``; ``singleton`` only when every measure says so. A table
    nothing measured is absent -- "not measured", never a guess either way."""
    from ..registry import loader
    from . import api_library as lib
    builds = sorted({v for v in (loader.version_of(a) for a in appliances) if v})
    seen: dict[str, set] = {}
    for v in builds:
        kinds = lib.object_kinds(product, v)
        if not kinds:
            continue
        urns = loader.registry_for(product, v)
        for t in tables:
            got = {kinds.get(lib.object_kind_key(c)) for c in (urns.get(t), t) if c}
            got.discard(None)
            if got:
                seen.setdefault(t, set()).update(got)
    wanted = set(tables)
    for tree in trees:
        for t, kind in ((tree or {}).get("shapes") or {}).items():
            if t in wanted and kind in ("table", "singleton"):
                seen.setdefault(t, set()).add(kind)
    return {t: ("table" if "table" in k else "singleton") for t, k in seen.items()}


def snapshot_for(appliance, *, timeout: float = 20.0) -> dict:
    """Product-aware config sweep: dispatch to the FortiADC, FortiAnalyzer,
    FortiAuthenticator, FortiGate or FortiWeb sweep by ``appliance.kind``. All return the same snapshot dict
    shape, so every downstream (cache ingest, JSON backup, git publish) is
    product-agnostic."""
    kind = str(getattr(appliance, "kind", "") or "").lower()
    if kind == "fortiadc":
        return snapshot_from_adc(appliance, timeout=timeout)
    if kind == "fortianalyzer":
        return snapshot_from_faz(appliance, timeout=timeout)
    if kind == "fortiauthenticator":
        return snapshot_from_fac(appliance, timeout=timeout)
    if kind == "fortigate":
        return snapshot_from_fgt(appliance, timeout=timeout)
    return snapshot_from_device(appliance, timeout=timeout)


def _fit(value, column):
    """Clamp a SyncRun label to the width its column actually declares.

    These are diagnostic labels. Overrunning one used to raise
    StringDataRightTruncation *on the flush*, which poisons the whole session —
    so a 3-character overrun in a bookkeeping field killed the caller's real
    work (2026-08-08: a WPP clone that had already been written to the
    appliance). A clipped label loses three characters of a diagnostic; the
    exception loses the transaction. The length is read off the model so this
    cannot drift if the column is ever widened, and
    ``tests/test_sync_trigger_width.py`` still fails the build for any literal
    that needs clipping — this is the backstop, not the guard.
    """
    if value is None:
        return None
    limit = getattr(getattr(column, "type", None), "length", None)
    text = str(value)
    return text[:limit] if limit else text


def record_coverage(appliance, snapshot: dict, *, session=None) -> None:
    """Replace the device's :class:`DeviceCoverage` row from a good sweep.

    A snapshot without ``answered`` (an imported or git-backfilled tree) says
    nothing about what the device served, so the existing row is kept."""
    from ..extensions import db
    from ..models_cache import DeviceCoverage
    answered = snapshot.get("answered")
    aid = getattr(appliance, "id", None)
    if aid is None or not isinstance(answered, dict):
        return
    from ..registry import loader
    session = session or db.session
    failed = {str(e.get("endpoint")): str(e.get("error") or "")[:160]
              for e in (snapshot.get("errors") or [])
              if isinstance(e, dict) and e.get("endpoint") and e.get("endpoint") != "_sweep"}
    row = session.get(DeviceCoverage, aid) or DeviceCoverage(appliance_id=aid)
    row.layer = "config"
    row.swept_at = datetime.utcnow()
    row.build = _fit(loader.version_of(appliance) or "", DeviceCoverage.build) or ""
    row.tables = dict(answered)
    row.failed = failed
    session.add(row)


def coverage_for(appliance_id: int, *, session=None):
    """The device's :class:`DeviceCoverage` row, or None (never swept with it)."""
    from ..extensions import db
    from ..models_cache import DeviceCoverage
    session = session or db.session
    try:
        return session.get(DeviceCoverage, appliance_id)
    except Exception:  # noqa: BLE001 — a reader degrades to "not known"
        session.rollback()
        return None


def persist_snapshot(appliance, snapshot: dict, *, source: str = "live",
                     trigger: str = "manual", user_label: str | None = None,
                     publish: bool = False, session=None):
    """Ingest into the cache, write the JSON backup, optionally git-publish it,
    and record a SyncRun. Returns the SyncRun (committed)."""
    from ..extensions import db
    from ..models_cache import SyncRun
    from . import device_store

    session = session or db.session
    library = snapshot.pop("_library", None)
    run = SyncRun(appliance_id=getattr(appliance, "id", None), section="_all",
                  trigger=_fit(trigger, SyncRun.trigger),
                  user_label=_fit(user_label, SyncRun.user_label), status="ok")
    session.add(run)
    session.flush()
    try:
        res = device_store.ingest_snapshot(appliance.id, snapshot, source=source,
                                           session=session)
        changed = sum(1 for v in res.values() if v.get("changed"))
        record_coverage(appliance, snapshot, session=session)
        p = write_device_json(appliance, snapshot)
        run.changed = changed
        run.detail = (f"{snapshot.get('total_objects', 0)} objects, "
                      f"{len(res)} sections, json={p.name}")
        try:
            from . import sot_store
            sr = sot_store.record(slugify(appliance.name), snapshot)
            run.detail += (" | sot: new version" if sr.get("changed")
                           else " | sot: unchanged")
        except Exception as exc:  # noqa: BLE001 — the store never sinks the sync
            run.detail += f" | sot error: {type(exc).__name__}"
        if publish:
            from . import sot_store
            try:
                # push, THEN evacuate the payload, THEN archive whole past
                # months of the change log — each step only ever deletes what
                # the server has been confirmed to hold, and the order is not
                # free: a month may leave only once its snapshots are off-box,
                # which is what the evacuation just did.
                pr = sot_store.offload()
                # 220, not 120: the summary now carries three clauses and the
                # third one is the only place the log archive is reported on a
                # scheduled run. A truncated line reads as "it did not run".
                run.detail += (f" | off-box: {pr.get('detail', '')[:220]}"
                               if pr.get("ok")
                               else f" | off-box: {pr.get('detail', '')[:80]}")
            except Exception as exc:  # noqa: BLE001 — push never sinks the sync
                run.detail += f" | off-box error: {type(exc).__name__}"
        run.status = "ok"
    except Exception as exc:  # noqa: BLE001
        run.status = "error"
        run.detail = f"{type(exc).__name__}: {exc}"[:240]
    run.finished_at = datetime.utcnow()
    session.commit()
    if library and run.status == "ok":
        _library_ingest(appliance, library)
    return run


def _library_ingest(appliance, library: dict) -> None:
    """File the REST rows a sweep read as API-library evidence of the build
    (``api_library.evidence_from_sweep``, the path the FortiWeb rediscovery
    takes). FortiGate's only REST evidence was its ``?action=schema``, which
    omits fields the GET returns (``web-svc-auto-restart`` on 8.0.1), so the
    library called them CLI-only. Never sinks the sync."""
    from ..extensions import db
    from . import api_library
    try:
        product = str(getattr(appliance, "kind", "") or "")
        device = {"appliance_id": appliance.id, "name": appliance.name,
                  "serial": str(getattr(appliance, "serial", "") or ""),
                  "model": str(getattr(appliance, "model", "") or ""),
                  "hw_type": str(getattr(appliance, "hw_type", "") or ""),
                  "firmware_raw": str(getattr(appliance, "firmware", "") or "")}
        ref = "sync:%d@%s" % (appliance.id, library.get("firmware") or "unversioned")
        doc = api_library.evidence_from_sweep(product, library, device, ref)
        api_library.ingest(doc)
    except Exception:  # noqa: BLE001
        db.session.rollback()


def sync_device(appliance, *, publish: bool = False, user_label: str | None = None,
                trigger: str = "manual", session=None):
    """Live sync one device: sweep -> ingest -> JSON -> (git) -> SyncRun.

    Product-aware: every device ADOM flows through here (the sweep is
    picked by ``kind`` in :func:`snapshot_for`)."""
    snapshot = snapshot_for(appliance)
    if not snapshot.get("total_objects"):
        # Device-level failure (license lock -20010, dead host, auth): EVERY
        # endpoint failed. Record an error run and do NOT ingest or overwrite
        # the JSON backup — the last good cache stays the source of truth.
        from ..extensions import db
        from ..models_cache import SyncRun
        session = session or db.session
        errs = snapshot.get("errors") or [{"error": "device returned no objects"}]
        run = SyncRun(appliance_id=getattr(appliance, "id", None), section="_all",
                      trigger=_fit(trigger, SyncRun.trigger),
                      user_label=_fit(user_label, SyncRun.user_label),
                      status="error",
                      detail=(f"device refused the sweep ({len(errs)} endpoints "
                              f"failed, 0 objects) — cache kept. First error: "
                              f"{errs[0].get('error', '')}")[:240])
        run.finished_at = datetime.utcnow()
        session.add(run)
        session.commit()
        return run
    return persist_snapshot(appliance, snapshot, source="live", trigger=trigger,
                            user_label=user_label, publish=publish, session=session)


def sync_fleet(appliances, *, publish: bool = False, user_label: str | None = None):
    """Sync several devices serially; one off-box blob push at the end if
    requested (the store dedups, so the push only carries what changed)."""
    runs = []
    for a in appliances:
        runs.append(sync_device(a, publish=False, user_label=user_label,
                                trigger="scheduled"))
    if publish:
        from . import sot_store
        try:
            sot_store.offload()
        except Exception:  # noqa: BLE001
            pass
    return runs


def backfill_from_git(*, session=None) -> dict:
    """Seed the cache from existing reports/<slug>/_config.json files (no box)."""
    from ..extensions import db
    from ..models import Appliance
    from . import device_store

    session = session or db.session
    out: dict = {}
    appliances = Appliance.query.all()
    by_slug = {slugify(a.name): a for a in appliances}
    by_id = {a.id: a for a in appliances}
    for cfg in sorted(_reports_dir().glob("*/_config.json")):
        try:
            snap = json.loads(cfg.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            out[cfg.parent.name] = "unreadable"
            continue
        aid = snap.get("appliance_id")
        appliance = by_id.get(aid) or by_slug.get(cfg.parent.name)
        if appliance is None:
            out[cfg.parent.name] = "no matching appliance"
            continue
        res = device_store.ingest_snapshot(appliance.id, snap, source="git",
                                           session=session)
        out[cfg.parent.name] = {"appliance_id": appliance.id, "sections": len(res)}
    return out


def deep_snapshot_from_device(appliance, *, timeout: float = 30.0,
                              progress=None, should_stop=None, workers: int = 1,
                              keep_alive: bool = False,
                              stats: dict | None = None,
                              factory_catalog: bool = True,
                              force_factory_walk: bool = False) -> dict:
    """Deep, read-only walk of every server policy + WPP -> enriched snapshot
    (by-parent sub-tables + named-rule objects nested under ``_deep``). Serial
    per box by default (gentle on the appliance); device-level fan-out lives in
    services.deep_jobs. ``progress``, ``should_stop``, ``workers`` and
    ``stats`` are handed to :func:`deep_capture.deep_sections` unchanged.

    ``workers`` > 1 and ``keep_alive`` (one reused connection pool for the
    whole walk) are what the rediscovery sweep asks for; every other caller
    keeps the defaults and the behaviour it had.

    ``factory_catalog`` (default on, every caller): predefined WPPs the
    catalog can vouch for on this appliance's firmware + API are replayed from
    it instead of walked, and the ones walked are recorded
    (``services.factory_catalog``). The snapshot's ``factory_catalog`` key
    says which were which. ``force_factory_walk`` reads every predefined
    profile in full this time. What was learned is stored even when a Stop
    ends the walk: each recorded profile was read completely."""
    import contextlib

    from .deep_capture import DeepCaptureStopped, FlaggingClient, deep_sections
    from ..clients.fortiweb import FortiWebClient
    from . import clone

    catalog = None
    client = FortiWebClient(appliance, timeout=timeout)
    if factory_catalog:
        from . import factory_catalog as fc
        if fc.enabled():
            catalog = fc.open_session(appliance, force_walk=force_factory_walk,
                                      firmware_raw=fc.live_firmware(client))
    reader = clone.ClientReader(FlaggingClient(client))
    try:
        with (client.keep_alive() if keep_alive else contextlib.nullcontext()):
            sections = deep_sections(reader, progress=progress,
                                     should_stop=should_stop, workers=workers,
                                     stats=stats, catalog=catalog)
    except DeepCaptureStopped:
        if catalog is not None:
            fc.persist(catalog, appliance)
        raise
    total = sum(len(rows) for sec in sections.values() for rows in sec.values())
    snap = {
        "device": appliance.name, "appliance_id": appliance.id,
        "generated_at": datetime.utcnow().isoformat(), "total_objects": total,
        "section_count": len(sections), "sections": sections, "errors": [],
    }
    if catalog is not None:
        snap["factory_catalog"] = fc.persist(catalog, appliance)
        if stats is not None:
            stats["catalog"] = snap["factory_catalog"]
    return snap


def persist_deep_snapshot(appliance, snapshot: dict, *, trigger: str = "deep",
                          user_label: str | None = None, session=None):
    """Atomic replace of the device's ``deep`` layer, then ingest the enriched
    snapshot under layer='deep' (per-device-per-layer freshness). Records a
    SyncRun. Returns the ingest result {section: {objects, changed}}."""
    from ..extensions import db
    from ..models_cache import SyncRun
    from . import device_store
    session = session or db.session
    run = SyncRun(appliance_id=getattr(appliance, "id", None), section="_deep",
                  trigger=_fit(trigger, SyncRun.trigger),
                  user_label=_fit(user_label, SyncRun.user_label), status="ok")
    session.add(run)
    session.flush()
    try:
        device_store.wipe_layer(appliance.id, "deep", session=session)
        res = device_store.ingest_snapshot(appliance.id, snapshot, source="live",
                                           layer="deep", session=session)
        run.changed = sum(1 for v in res.values() if v.get("changed"))
        run.detail = (f"{snapshot.get('total_objects', 0)} deep objects, "
                      f"{len(res)} sections")
        run.status = "ok"
    except Exception as exc:  # noqa: BLE001
        res = {}
        run.status = "error"
        run.detail = f"{type(exc).__name__}: {exc}"[:240]
    run.finished_at = datetime.utcnow()
    session.commit()
    return res
