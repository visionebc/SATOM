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
* **tables**, each in one mode:

  - ``all`` (default): the source block replaces the target's whole;
  - excluded (``exclude``): the target keeps its own;
  - picked (``picks``): only the chosen objects, MERGED into the target's
    table (same name replaced, the target's other objects kept), plus every
    object they reference (:func:`plan` follows the references);
  - a domain in ``only_picked`` copies nothing but what is picked and what
    the picks need.

  Global tables with objects are always merged, never replaced: the target's
  other ADOMs use them too (a global virtual IP, a certificate).
* **identity stays the target's** -- hostname, interfaces, routes, DNS, NTP,
  SNMP, HA, administrators, their certificates, access policy and login
  message (:data:`IDENTITY_TABLES`). Copying them would bring the source's
  management address up on the new box: an address conflict, and SATOM loses
  the box. ADOM mode itself is ``system global`` (``adom-admin``), so it is
  the target's too.
* **ADOM membership** -- on a box with ADOMs a global object says which ADOMs
  may use it (``set domains root adom_a``; measured on fortiweb21, 7.6.8: a
  virtual IP without it is dropped by the restore). Copied global objects get
  their ``domains`` translated through the domain map; a virtual IP that has
  none (it comes from a box without ADOMs) gets the mapped target domains. On
  a box without ADOMs the field is removed.
* **dummy IPs** -- the address of every copied virtual IP (``system vip``) is
  rewritten with the fleet's clone rules (``clone_rules.dummy_ip``) so the copy
  takes no traffic while the source still answers on the real one.

The plan reports what it copies, what stays the target's, what is excluded,
what was picked and what came along as a dependency, every rewritten address,
every reference a copied object makes to an object that will not exist on the
target, the objects a FortiWeb restore drops (:data:`DROPPED_BY_RESTORE`) and
what the read-back must find (``expected_counts`` / ``expected_names``).

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
    # the dashboard is drawn per administrator (widget-table sys_admin_<n>_<domain>);
    # a no-defaults backup prints it in global, a full dump per domain
    "global:system dashboard-widget",
    # the administrators' login page; a box with ADOMs refuses it inside an
    # ADOM (measured: dropped from adom_a on fortiweb21)
    "global:system replacemsg-admin",
    # per domain: who administers it, how its dashboard looks, its login page
    "*:system admin", "*:system dashboard-widget", "*:system replacemsg-admin",
})

#: Content a FortiWeb restore puts back WITHOUT the object: measured 2026-10-15
#: on 7.6.8 and 8.0.6 (``waf_artifacts``) -- the objects are dropped, not even
#: the name survives. Reported, never counted as copied.
DROPPED_BY_RESTORE = frozenset({"waf xml-schema file", "waf xml-wsdl file",
                                "waf grpc-idl file"})

#: Global tables whose objects a box with ADOMs drops without ``set domains``.
DOMAIN_SCOPED_GLOBAL = frozenset({"system vip"})

#: Global tables a ``show full-configuration`` ALSO prints inside every domain
#: (measured on 7.6.8: byte for byte the global one; a CLI backup never does).
#: The domain copy is a view: never written, the object travels with global.
GLOBAL_VIEWS = frozenset({"system vip"})

_VIP_LINE = re.compile(r"^(\s*set vip )(\d{1,3}(?:\.\d{1,3}){3})(/\d{1,2})?\s*$")
_EDIT = re.compile(r'^  edit "?([^"]*)"?\s*$')
_DOMAINS = re.compile(r"^    set domains (.*)$")


class MigrationError(ValueError):
    """The selection cannot be built into a package; the message says why."""


# --------------------------------------------------------------------------- #
#  Blocks and entries                                                          #
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


def split_entries(lines: list[str]) -> dict[str, list[str]] | None:
    """``{name: lines}`` of a table whose body is only ``edit … next`` rows
    (the ``config``/``end`` lines excluded), or ``None`` for a settings block
    (``set`` lines directly under the table) -- that one can only be copied
    whole."""
    body, cont = lines[1:-1], pkg._continuations(lines[1:-1])
    out: dict[str, list[str]] = {}
    cur: list[str] | None = None
    for line, c in zip(body, cont):
        if cur is None:
            m = None if c else _EDIT.match(line)
            if not m:
                if not line.strip():
                    continue
                return None
            cur = [line]
            out[m.group(1)] = cur
            continue
        cur.append(line)
        if not c and line == "  next":
            cur = None
    if cur is not None:
        return None
    return out


def _join(head: str, ents: list[list[str]]) -> list[str]:
    return [head, *[l for e in ents for l in e], "end"]


def inventory(data: bytes) -> dict[str, dict[str, int]]:
    """``{domain: {table: entries}}`` of a dump or package -- what there is to
    migrate (tables with no entries are settings blocks: entries = 0)."""
    return {dom: {t: len(entries(lines)) for t, lines in blocks(body)}
            for dom, body in pkg.package_sections(data).items()}


def names_inventory(data: bytes) -> dict[str, dict[str, list[str]]]:
    """``{domain: {table: [entry names]}}`` -- what can be picked."""
    return {dom: {t: entries(lines) for t, lines in blocks(body)}
            for dom, body in pkg.package_sections(data).items()}


def names_by_table(sections: dict[str, list[str]]) -> dict[str, set[str]]:
    """``{"<domain>:<table>": {names}}`` of a configuration (the read-back)."""
    return {f"{dom}:{t}": set(entries(lines))
            for dom, body in sections.items() for t, lines in blocks(body)}


def is_identity(domain: str, table: str) -> bool:
    """Whether ``domain:table`` describes the box (always the target's)."""
    return (f"{domain}:{table}" in IDENTITY_TABLES
            or (domain != "global" and f"*:{table}" in IDENTITY_TABLES))


def adom_mode(global_body: list[str]) -> bool:
    """``set adom-admin enable`` in ``system global``."""
    for t, lines in blocks(global_body):
        if t == "system global":
            return any(l.strip() == "set adom-admin enable" for l in lines)
    return False


# --------------------------------------------------------------------------- #
#  Rewrites                                                                    #
# --------------------------------------------------------------------------- #
#: Where a dummy address comes from when the clone rule gives one already
#: used: the RFC 2544 benchmarking range, never routed on a real network.
UNIQUE_DUMMY_NET = "198.18.0.0/15"


def unique_dummy(rule: Callable[[str], str],
                 taken: set[str] | frozenset = frozenset()) -> Callable[[str, str], str]:
    """``rule`` (the fleet's clone rule), made unique per migration. A single
    policy clone may share the fallback address; a whole box cannot: the
    copy would carry tens of virtual IPs on one address. A repeat is replaced
    by the next free address of :data:`UNIQUE_DUMMY_NET`.

    Stable per virtual IP: a FortiWeb dump lists the ``system vip`` table in
    ``global`` AND in every domain (byte for byte the same object, measured on
    7.6.8), so one VIP must get one address wherever it is printed.

    ``taken``: addresses the target keeps (its own virtual IPs that the
    migration does not replace) -- a dummy never lands on one of them."""
    import ipaddress
    used: set[str] = set(taken)
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


def _dummy_vips(lines: list[str], transform, domain: str, log: list[dict]) -> list[str]:
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


def _domains_of(lines: list[str] | None) -> list[str] | None:
    for l in lines or []:
        m = _DOMAINS.match(l)
        if m:
            return m.group(1).split()
    return None


def _vip_address(lines: list[str]) -> str:
    for l in lines:
        m = _VIP_LINE.match(l)
        if m:
            return m.group(2)
    return ""


def _fix_domains(entry: list[str], table: str, dmap: dict[str, str], tgt_adom: bool,
                 targets: list[str], existing: list[str] | None) -> list[str]:
    """ADOM membership of one copied GLOBAL object (see the module docstring).
    ``existing`` is the target's own entry of the same name, whose ADOMs are
    kept (a merge must not take a shared object away from another ADOM)."""
    _doms = _domains_of
    src = _doms(entry)
    body = [l for l in entry if not _DOMAINS.match(l)]
    if not tgt_adom:
        return body
    if src is None and table not in DOMAIN_SCOPED_GLOBAL:
        return entry
    mapped = [dmap[d] for d in (src or []) if d in dmap]
    want = mapped or list(targets)
    for d in _doms(existing) or []:
        if d not in want:
            want.append(d)
    return body[:-1] + [f"    set domains {' '.join(sorted(want))} "] + body[-1:]


def _ref_tokens(lines: list[str]) -> set[str]:
    """Names a copied object may reference: the unquoted values of its
    ``set`` lines (a quoted value is text -- a comment, a script)."""
    out: set[str] = set()
    for line, c in zip(lines, pkg._continuations(lines)):
        s = line.strip()
        if c or not s.startswith("set ") or '"' in s:
            continue
        out.update(s.split()[2:])
    return out


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


def plan(source: bytes, target_backup: bytes, *, domains: dict[str, str],
         copy_global: bool = True, exclude: set[str] | frozenset = frozenset(),
         dummy: Callable[[str], str] | None = None,
         picks: dict[str, set[str]] | None = None,
         only_picked: set[str] | frozenset = frozenset()) -> tuple[bytes, dict[str, Any]]:
    """Build the target package and the report.

    ``source`` is a CLI dump or a package of the source box; ``target_backup``
    the target's own CLI backup (its header and its current configuration).
    ``domains`` maps source domain -> target domain. ``exclude`` and the keys
    of ``picks`` are ``"<source domain>:<table>"`` (``global:<table>`` for
    global); ``only_picked`` holds source domains (or ``global``) that copy
    only picks and what they need. ``dummy`` rewrites a VIP address (``None``
    = keep the real ones); it is made unique per migration."""
    src = pkg.package_sections(source)
    tgt_pkg = pkg.parse_package_text(pkg.package_text(target_backup))
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

    dmap = dict(sorted(domains.items()))
    targets = sorted(dmap.values())
    pairs = ([("global", "global")] if copy_global else []) + list(dmap.items())
    active = {s for s, _ in pairs}
    tgt_adom = adom_mode(tgt.get("global", []))
    sblocks = {d: dict(blocks(src[d])) for d in active}
    sents = {d: {t: split_entries(l) for t, l in bl.items()} for d, bl in sblocks.items()}
    exclude = set(exclude)
    only_picked = set(only_picked)

    # Virtual IPs the target already has. One that an ADOM this migration does
    # not touch also uses is SHARED: it is kept as it is (only opened to the
    # mapped ADOMs) -- replacing it would move a live object of another ADOM.
    # The addresses the target keeps are never handed out as dummies.
    tgt_vips = split_entries(dict(blocks(tgt.get("global", []))).get("system vip")
                             or ["config system vip", "end"]) or {}
    src_vip_names = set()
    for d in active:
        src_vip_names |= set((sents[d].get("system vip") or {}))
    shared_vips = {n for n, e in tgt_vips.items()
                   if tgt_adom and n in src_vip_names
                   and set(_domains_of(e) or []) - set(targets)}
    taken = {_vip_address(e) for n, e in tgt_vips.items()
             if n not in src_vip_names or n in shared_vips} - {""}
    vip_dummy = unique_dummy(dummy, taken) if dummy is not None else None

    picks = {k: set(v) for k, v in (picks or {}).items() if v}
    for key, names in picks.items():
        sdom, _, table = key.partition(":")
        if sdom not in active:
            raise MigrationError(f"{key}: domain {sdom!r} is not being migrated")
        if table not in sblocks[sdom]:
            raise MigrationError(f"{key}: the source has no such table")
        if is_identity(sdom, table):
            raise MigrationError(f"{key} is the box identity; the target keeps its own")
        if key in exclude:
            raise MigrationError(f"{key} is both excluded and picked")
        if sents[sdom][table] is None:
            raise MigrationError(f"{key} is a settings table; it can only be copied whole")
        missing = sorted(names - set(sents[sdom][table]))
        if missing:
            raise MigrationError(f"{key} has no object(s) {', '.join(missing)}")

    def mode(sdom: str, table: str) -> str:
        key = f"{sdom}:{table}"
        if sdom != "global" and table in GLOBAL_VIEWS:
            return "view"
        if is_identity(sdom, table):
            return "identity"
        if key in exclude:
            return "excluded"
        if key in picks:
            return "pick"
        if sdom in only_picked:
            return "dep"
        if sdom == "global" and sents[sdom].get(table) is not None:
            return "merge"
        return "all"

    # Follow the references of every pick: an object it names, defined in the
    # same source domain or in global, comes along if its table is pickable.
    index: dict[str, dict[str, list[str]]] = {}
    for d in active:
        for t, ents in sents[d].items():
            for n in (ents or {}):
                index.setdefault(d, {}).setdefault(n, []).append(t)
    chosen = {k: set(v) for k, v in picks.items()}
    deps: list[str] = []
    queue = [(k, n) for k, ns in picks.items() for n in sorted(ns)]
    while queue:
        key, name = queue.pop(0)
        sdom, _, table = key.partition(":")
        for tok in sorted(_ref_tokens(sents[sdom][table][name])):
            for d in (sdom, "global"):
                if d not in active:
                    continue
                for t in index.get(d, {}).get(tok, []):
                    if mode(d, t) not in ("pick", "dep"):
                        continue
                    dk = f"{d}:{t}"
                    if tok in chosen.get(dk, set()):
                        continue
                    chosen.setdefault(dk, set()).add(tok)
                    deps.append(f'{dk} "{tok}" (needed by {key} "{name}")')
                    queue.append((dk, tok))

    report: dict[str, Any] = {
        "domains": [{"source": s, "target": t} for s, t in dmap.items()],
        "copy_global": copy_global, "target_adoms": tgt_adom,
        "copied": {}, "kept_from_target": {}, "identity_kept": [], "excluded": [],
        "picked": {k: sorted(v) for k, v in picks.items()}, "dependencies": deps,
        "merged": {}, "shared_kept": [], "dropped_by_restore": {}, "dummy_ips": [],
        "dangling": [],
        "expected_counts": {}, "expected_names": {},
        "untouched_domains": sorted(d for d in tgt if d != "global" and d not in dmap.values()),
        "not_copied_source_domains": sorted(d for d in src if d != "global" and d not in dmap),
    }
    merged: dict[str, list[tuple[str, list[str]]]] = {d: blocks(b) for d, b in tgt.items()}
    written: dict[str, list[tuple[str, list[str]]]] = {}   # tdom -> (table, lines) written

    def rewrite(sdom, tdom, table, lines):
        if vip_dummy is not None and table == "system vip":
            lines = _dummy_vips(lines, vip_dummy, tdom, report["dummy_ips"])
        return lines

    for sdom, tdom in pairs:
        tbl = dict(merged[tdom])
        order = _merge_order(list(sblocks[sdom]), [n for n, _ in merged[tdom]])
        new: list[tuple[str, list[str]]] = []
        for table in order:
            key, tkey = f"{sdom}:{table}", f"{tdom}:{table}"
            have = table in sblocks[sdom]
            m = mode(sdom, table) if have else "absent"
            if m == "identity":
                report["identity_kept"].append(tkey)
            elif m == "excluded":
                report["excluded"].append(key)
            take_all = m == "all"
            take_some = sorted(chosen.get(key, set())) if m in ("pick", "dep") else \
                (list(sents[sdom][table]) if m == "merge" else [])
            if take_all:
                lines = rewrite(sdom, tdom, table, sblocks[sdom][table])
                new.append((table, lines))
                written.setdefault(tdom, []).append((table, lines))
                n = len(entries(lines))
                if table in DROPPED_BY_RESTORE and n:
                    report["dropped_by_restore"][tkey] = n
                elif n:
                    report["copied"][tkey] = n
                    report["expected_counts"][tkey] = n
            elif take_some:
                src_ents = sents[sdom][table]
                tgt_lines = tbl.get(table)
                tgt_ents = split_entries(tgt_lines) if tgt_lines else {}
                if tgt_ents is None:
                    raise MigrationError(f"{tkey}: the target's table is a settings block")
                out = dict(tgt_ents)
                for n in take_some:
                    ent = src_ents[n]
                    if sdom == "global" and table == "system vip" and n in shared_vips:
                        out[n] = _fix_domains(tgt_ents[n], table, {}, tgt_adom, targets,
                                              tgt_ents[n])
                        report["shared_kept"].append(f'{tkey} "{n}"')
                        continue
                    if sdom == "global":
                        ent = _fix_domains(ent, table, dmap, tgt_adom, targets, tgt_ents.get(n))
                    ent = rewrite(sdom, tdom, table, ent)
                    out[n] = ent
                    written.setdefault(tdom, []).append((table, ent))
                head = (tgt_lines or sblocks[sdom][table])[0]
                new.append((table, _join(head, list(out.values()))))
                kept = len(set(tgt_ents) - set(take_some))
                if table in DROPPED_BY_RESTORE:
                    report["dropped_by_restore"][tkey] = len(take_some)
                else:
                    report["copied"][tkey] = len(take_some)
                    report["expected_names"][tkey] = take_some
                    if kept:
                        report["merged"][tkey] = kept
            elif table in tbl:
                new.append((table, tbl[table]))
                n = len(entries(tbl[table]))
                if n and m != "identity":
                    report["kept_from_target"][tkey] = n
        merged[tdom] = new

    # References from what was written to source objects the target lacks.
    src_names = {d: {n for t in sents[d].values() if t for n in t} for d in active}
    have = {d: {n for _, l in bl for n in entries(l)} for d, bl in merged.items()}
    dangling = set()
    for sdom, tdom in pairs:
        known = src_names.get(sdom, set()) | src_names.get("global", set())
        ok = have.get(tdom, set()) | have.get("global", set())
        for table, lines in written.get(tdom, []):
            obj = ""
            for line, c in zip(lines, pkg._continuations(lines)):
                if c:
                    continue
                m = _EDIT.match(line)
                if m:
                    obj = m.group(1)
                    continue
                for tok in _ref_tokens([line]):
                    if tok in known and tok not in ok:
                        dangling.add(f'{tdom}:{table} "{obj}" -> {tok}')
    report["dangling"] = sorted(dangling)
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


__all__ = ["IDENTITY_TABLES", "DROPPED_BY_RESTORE", "DOMAIN_SCOPED_GLOBAL", "MigrationError",
           "GLOBAL_VIEWS", "adom_mode", "blocks", "entries", "inventory", "is_identity", "names_by_table",
           "names_inventory", "plan", "split_entries", "unique_dummy"]
