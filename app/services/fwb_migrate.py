"""Device-to-device migration of a FortiWeb configuration -- the planner.

A migration builds ONE configuration package for the TARGET box and restores
it there (:func:`app.services.backup.restore`, which then reads it back). The
package starts from the target's own CLI backup and takes from the SOURCE only
what the operator selected:

* **domains** -- which source domain lands in which target domain. A FortiWeb
  ADOM is a domain (``config vdom`` / ``edit <adom>`` in a dump, one ``[file]``
  section in a package); a box without ADOMs has one, ``root``. So "ADOM to a
  box without ADOMs" is ``{"adom1": "root"}``, "box without ADOMs to an ADOM"
  is ``{"root": "adom1"}``, and several ADOMs is several pairs. A source domain
  with no pair is not copied; a target domain no pair lands in keeps its own
  configuration.
* **tables** -- every top-level ``config <table>`` block of a mapped domain
  (and of ``global``) is copied unless excluded; a copied block replaces the
  target's block whole. ``global`` can be left out entirely.
* **identity stays the target's** -- hostname, interfaces, routes, DNS, NTP,
  SNMP, HA, administrators and their certificates and access policy
  (:data:`IDENTITY_TABLES`). Copying them would bring the source's management
  address up on the new box: an address conflict, and SATOM loses the box.
  ADOM mode itself is ``system global`` (``adom-admin``), so it is the
  target's too.
* **dummy IPs** -- the address of every copied virtual IP (``system vip``) is
  rewritten with the fleet's clone rules (``clone_rules.dummy_ip``) so the copy
  takes no traffic while the source still answers on the real one.

The plan reports what it copies (entries per table), what stays the target's,
what is excluded, every rewritten address, every reference a copied object
makes to an object that will not exist on the target, and the objects a
FortiWeb restore drops (:data:`DROPPED_BY_RESTORE`).

Pure: bytes and dicts in, bytes and a dict out -- no Flask, no device I/O.
"""
from __future__ import annotations

import io
import re
import zipfile
from typing import Any, Callable

from . import fwb_config_package as pkg

#: Tables that describe the BOX, not the service it runs. Always the target's.
IDENTITY_TABLES = frozenset({
    "global:system global", "global:system interface", "global:system admin",
    "global:user admin-usergrp", "global:system ha", "global:system dns",
    "global:router static", "global:router policy", "global:router setting",
    "global:system ntp", "global:system snmp sysinfo", "global:system snmp community",
    "global:system snmp user", "global:system admin-certificate local",
    "global:system admin-certificate ca", "global:system admin-certificate intermediate-ca",
    "global:system admin-certificate intermediate-ca-group",
    "global:system admin-certificate remote", "global:system firewall admin-policy",
    "global:system sso-admin",
    # per domain: who administers it and how its dashboard looks
    "*:system admin", "*:system dashboard-widget",
})

#: Content a FortiWeb restore puts back WITHOUT the object: measured 2026-10-15
#: on 7.6.8 and 8.0.6 (``waf_artifacts``) -- the objects are dropped, not even
#: the name survives. Reported, never counted as copied.
DROPPED_BY_RESTORE = frozenset({"waf xml-schema file", "waf xml-wsdl file",
                                "waf grpc-idl file"})

_VIP_LINE = re.compile(r"^(\s*set vip )(\d{1,3}(?:\.\d{1,3}){3})(/\d{1,2})?\s*$")
_EDIT = re.compile(r'^  edit "?([^"]*)"?\s*$')


class MigrationError(ValueError):
    """The selection cannot be built into a package; the message says why."""


# --------------------------------------------------------------------------- #
#  Blocks                                                                      #
# --------------------------------------------------------------------------- #
def blocks(body: list[str]) -> list[tuple[str, list[str]]]:
    """``[(table, lines)]`` -- the top-level ``config <table> … end`` blocks of
    one domain body, in order, each with its own ``config``/``end`` lines.
    Lines between blocks are not expected; a body that has them is refused."""
    out: list[tuple[str, list[str]]] = []
    cont = pkg._continuations(body)
    cur: tuple[str, list[str]] | None = None
    for line, c in zip(body, cont):
        if cur is not None:
            cur[1].append(line)
            if not c and line == "end":
                out.append(cur)
                cur = None
            continue
        if not line.strip():
            continue
        if c or not line.startswith("config "):
            raise MigrationError(f"unexpected line outside a config block: {line[:60]!r}")
        cur = (line[7:].strip(), [line])
    if cur is not None:
        raise MigrationError(f"block {cur[0]!r} is never closed")
    names = [n for n, _ in out]
    dup = sorted({n for n in names if names.count(n) > 1})
    if dup:
        raise MigrationError(f"table(s) appear twice in one domain: {', '.join(dup)}")
    return out


def entries(lines: list[str]) -> list[str]:
    """Names of the ``edit`` rows directly under a block."""
    out = []
    for line, c in zip(lines, pkg._continuations(lines)):
        if not c:
            m = _EDIT.match(line)
            if m:
                out.append(m.group(1))
    return out


def inventory(data: bytes) -> dict[str, dict[str, int]]:
    """``{domain: {table: entries}}`` of a dump or package -- what there is to
    migrate (tables with no entries are settings blocks: entries = 0)."""
    return {dom: {t: len(entries(lines)) for t, lines in blocks(body)}
            for dom, body in pkg.package_sections(data).items()}


def _is_identity(domain: str, table: str) -> bool:
    return (f"{domain}:{table}" in IDENTITY_TABLES
            or (domain != "global" and f"*:{table}" in IDENTITY_TABLES))


# --------------------------------------------------------------------------- #
#  Merge                                                                       #
# --------------------------------------------------------------------------- #
def _merge_order(src_order: list[str], tgt_order: list[str]) -> list[str]:
    """Source order first (it is the box's own dependency order); a table only
    the target has is placed right after the table that precedes it there."""
    out = list(src_order)
    seen = set(out)
    for i, t in enumerate(tgt_order):
        if t in seen:
            continue
        prev = next((tgt_order[j] for j in range(i - 1, -1, -1) if tgt_order[j] in seen), None)
        out.insert(out.index(prev) + 1 if prev else 0, t)
        seen.add(t)
    return out


def _dummy_vips(lines: list[str], transform: Callable[[str], str],
                domain: str, log: list[dict]) -> list[str]:
    out, current = [], ""
    for line, c in zip(lines, pkg._continuations(lines)):
        if not c:
            m = _EDIT.match(line)
            if m:
                current = m.group(1)
            v = _VIP_LINE.match(line)
            if v:
                new = transform(v.group(2), current)
                if new != v.group(2) and not any(e["vip"] == current and e["to"].split("/")[0] == new
                                                 for e in log):
                    log.append({"domain": domain, "vip": current,
                                "from": v.group(2) + (v.group(3) or ""),
                                "to": new + (v.group(3) or "")})
                line = f"{v.group(1)}{new}{v.group(3) or ''}"
        out.append(line)
    return out


#: Where a dummy address comes from when the clone rule gives one already
#: used: the RFC 2544 benchmarking range, never routed on a real network.
UNIQUE_DUMMY_NET = "198.18.0.0/15"


def unique_dummy(rule: Callable[[str], str]) -> Callable[[str], str]:
    """``rule`` (the fleet's clone rule), made unique per migration. A single
    policy clone may share the fallback address; a whole box cannot: the
    copy would carry tens of virtual IPs on one address. A repeat is replaced
    by the next free address of :data:`UNIQUE_DUMMY_NET`.

    Stable per virtual IP: a FortiWeb dump lists the ``system vip`` table in
    ``global`` AND in every domain (byte for byte the same object, measured on
    7.6.8), so one VIP must get one address wherever it is printed."""
    import ipaddress
    used: set[str] = set()
    seen: dict[tuple[str, str], str] = {}
    free = (str(h) for h in ipaddress.IPv4Network(UNIQUE_DUMMY_NET).hosts())

    def _pick(ip: str, name: str = "") -> str:
        if (name, ip) in seen:
            return seen[(name, ip)]
        new = rule(ip)
        while new in used:
            new = next(free)
        used.add(new)
        seen[(name, ip)] = new
        return new
    return _pick


def _names(merged: dict[str, list[tuple[str, list[str]]]]) -> dict[str, set[str]]:
    return {dom: {n for _, lines in bl for n in entries(lines)} for dom, bl in merged.items()}


def _dangling(copied: dict[str, list[tuple[str, list[str]]]], src_names: dict[str, set[str]],
              merged_names: dict[str, set[str]], dmap: dict[str, str]) -> list[str]:
    """References from copied objects to source objects that will not exist on
    the target. A reference is a ``set`` value naming an object the SOURCE
    defines (in the same domain or in ``global``)."""
    out = []
    for tdom, bl in copied.items():
        sdom = next((s for s, t in dmap.items() if t == tdom), tdom)
        known_src = src_names.get(sdom, set()) | src_names.get("global", set())
        have = merged_names.get(tdom, set()) | merged_names.get("global", set())
        for table, lines in bl:
            obj = ""
            for line, c in zip(lines, pkg._continuations(lines)):
                if c:
                    continue
                m = _EDIT.match(line)
                if m:
                    obj = m.group(1)
                    continue
                s = line.strip()
                if not s.startswith("set ") or '"' in s:
                    continue
                for tok in s.split()[2:]:
                    if tok in known_src and tok not in have:
                        out.append(f'{tdom}:{table} "{obj}" -> {tok}')
    return sorted(set(out))


def plan(source: bytes, target_backup: bytes, *, domains: dict[str, str],
         copy_global: bool = True, exclude: set[str] | frozenset = frozenset(),
         dummy: Callable[[str], str] | None = None) -> tuple[bytes, dict[str, Any]]:
    """Build the target package and the report.

    ``source`` is a CLI dump or a package of the source box; ``target_backup``
    the target's own CLI backup (its header and its current configuration).
    ``domains`` maps source domain -> target domain. ``exclude`` holds
    ``"<source domain>:<table>"`` keys (``global:<table>`` for global).
    ``dummy`` rewrites a VIP address (``None`` = keep the real ones); it is
    made unique per migration (:func:`unique_dummy`)."""
    if dummy is not None:
        dummy = unique_dummy(dummy)
    src = pkg.package_sections(source)
    tgt_text = pkg.package_text(target_backup)
    tgt_pkg = pkg.parse_package_text(tgt_text)
    tgt = {s["domain"]: s["body"] for s in tgt_pkg["sections"]}

    if not domains:
        raise MigrationError("no domain selected: map at least one source domain to a target domain")
    for s, t in domains.items():
        if s == "global" or t == "global":
            raise MigrationError("global is not a domain to map; it is copied with copy_global")
        if s not in src:
            raise MigrationError(f"the source has no domain {s!r} (it has {sorted(d for d in src if d != 'global')})")
        if t not in tgt:
            raise MigrationError(f"the target has no domain {t!r} (it has {sorted(d for d in tgt if d != 'global')})")
    if len(set(domains.values())) != len(domains):
        raise MigrationError("two source domains map to the same target domain")

    pairs = ([("global", "global")] if copy_global else []) + sorted(domains.items())
    report: dict[str, Any] = {
        "domains": [{"source": s, "target": t} for s, t in sorted(domains.items())],
        "copy_global": copy_global, "copied": {}, "kept_from_target": {}, "identity_kept": [],
        "excluded": [], "dropped_by_restore": {}, "dummy_ips": [], "dangling": [],
        "untouched_domains": sorted(d for d in tgt if d != "global" and d not in domains.values()),
        "not_copied_source_domains": sorted(d for d in src if d != "global" and d not in domains),
    }
    merged: dict[str, list[tuple[str, list[str]]]] = {}
    copied: dict[str, list[tuple[str, list[str]]]] = {}
    for tdom, body in tgt.items():
        merged[tdom] = blocks(body)
    for sdom, tdom in pairs:
        sbl = dict(blocks(src[sdom]))
        tbl = dict(merged[tdom])
        order = _merge_order(list(sbl), [n for n, _ in merged[tdom]])
        new: list[tuple[str, list[str]]] = []
        for table in order:
            key = f"{sdom}:{table}"
            take = table in sbl and not _is_identity(sdom, table) and key not in exclude
            if table in sbl and _is_identity(sdom, table):
                report["identity_kept"].append(f"{tdom}:{table}")
            elif table in sbl and key in exclude:
                report["excluded"].append(key)
            if take:
                lines = sbl[table]
                if dummy is not None and table == "system vip":
                    lines = _dummy_vips(lines, dummy, tdom, report["dummy_ips"])
                new.append((table, lines))
                copied.setdefault(tdom, []).append((table, lines))
                n = len(entries(lines))
                if table in DROPPED_BY_RESTORE and n:
                    report["dropped_by_restore"][f"{tdom}:{table}"] = n
                elif n:
                    report["copied"][f"{tdom}:{table}"] = n
            elif table in tbl:
                new.append((table, tbl[table]))
                n = len(entries(tbl[table]))
                if n:
                    report["kept_from_target"][f"{tdom}:{table}"] = n
        merged[tdom] = new

    report["dangling"] = _dangling(
        copied, {d: {n for _, l in blocks(b) for n in entries(l)} for d, b in src.items()},
        _names(merged), {**dict(pairs)})
    report["objects"] = sum(report["copied"].values())

    out = list(tgt_pkg["header"])
    for s in tgt_pkg["sections"]:
        body = [l for _, lines in merged[s["domain"]] for l in lines]
        out += ["[file]", *s["meta"], tgt_pkg["split"], *s["comments"], *body,
                tgt_pkg["split"], "[/file]"]
    buf = io.BytesIO()
    member = pkg._zip_member(target_backup)[0]
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(member, "\n".join(out) + "\n")
    return buf.getvalue(), report


__all__ = ["IDENTITY_TABLES", "DROPPED_BY_RESTORE", "MigrationError", "blocks",
           "entries", "inventory", "plan"]
