"""Naming discovery — read the names a device already uses and infer the
convention behind them, per object type.

The Naming page's scheme editor (:mod:`services.naming`) is PRESCRIPTIVE: the
operator says how NEW objects are named. This module is DESCRIPTIVE: it reads
the configuration tree SATOM already holds for a device (``device_sync``'s
``data/reports/<slug>/_config.json`` — no device call) and, for every object
type, reports:

* the dominant pattern (``pol-{adom}-{name}``) and how many objects follow it;
* variants — another prefix used by part of the objects;
* exceptions, each with the reason it does not fit. The most useful one is a
  part that matches a field on most objects but not on this one: "the name
  says https, the object's port says 8080" is a stale name;
* factory objects, counted apart and never used to infer anything (the
  vendor's ``LB_HLTHCK_ICMP`` says nothing about the team's convention).

Tokens. A part of a name becomes:

``literal``
    the same text on (nearly) every object: ``pol``.
``{port} {proto} {adom} {device} {host} {ip} {<field>}``
    equals a field of the SAME object (or the device context: its ADOM/VDOM,
    its name) on (nearly) every object. Correlating with the object instead of
    guessing from the text is what tells a port from any other number.
``{num}``
    digits that match no field.
``{name}``
    the free part (the site / application identifier). It is the scheme's own
    token, so a discovered pattern made only of literals and ``{name}`` can be
    applied to the Naming scheme as it is.

Factory objects: the device's own flag first (:data:`FACTORY_FLAGS`), then the
measured factory-name list (``registry/data/naming_factory.json``) for vendor
objects the device does not flag, then physical port names. Every factory
verdict carries its reason, so a wrong one is visible.

Pure: no Flask, no database. :func:`load_tree` is the only I/O.
"""
from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from pathlib import Path

#: Share of the objects a position must agree on to become part of the pattern.
THRESHOLD = 0.8
#: Objects sharing a prefix before that prefix counts as a convention.
MIN_CLUSTER = 2
#: Fields that carry an object's name, in the order the products use them.
NAME_KEYS = ("name", "mkey", "username", "userid")

#: Free text an operator types: it repeats the name's words, so a match with
#: it is an echo, not a convention.
FREE_TEXT_KEYS = frozenset({"comment", "comments", "description", "desc", "remark",
                            "remarks", "title", "note", "notes", "disp-name",
                            "display-name", "display_name", "displayname", "label"})

_SPLIT = re.compile(r"([-_.\s]+)")
_TOKEN_RE = re.compile(r"\{([a-z0-9_-]+)\}")

#: Ports whose service word is what a name usually carries (``vs-www-https``).
PORT_WORDS = {
    "21": "ftp", "22": "ssh", "23": "telnet", "25": "smtp", "53": "dns",
    "80": "http", "110": "pop3", "143": "imap", "389": "ldap", "443": "https",
    "465": "smtps", "636": "ldaps", "993": "imaps", "995": "pop3s",
    "1812": "radius", "3389": "rdp", "8080": "http", "8443": "https",
}
PROTO_WORDS = frozenset(set(PORT_WORDS.values()) | {
    "tcp", "udp", "tls", "ssl", "ftps", "icmp", "sip", "grpc", "ws", "wss",
    "quic", "h2", "http2", "http3", "mtls", "tcps",
})

#: Device flags that mark a predefined object, per product: (field, values).
#: FortiWeb's is ``clone_scope.FACTORY_FIELD`` (``can_view``; its
#: ``is_default`` came back None for every object on 7.6.8) — a test pins the
#: two together. FortiADC: ``_nondeletable``. FortiGate: ``q_static`` (the
#: sweep reads with ``with_meta=1``) and the certificate ``source``.
#: FortiAnalyzer: ``protected`` (1306 of 1311 report charts on faz02).
FACTORY_FLAGS: dict[str, tuple[tuple[str, frozenset], ...]] = {
    "fortiweb": (("can_view", frozenset({"1", "true"})),),
    "fortiadc": (("_nondeletable", frozenset({"1", "true"})),),
    "fortigate": (("q_static", frozenset({"1", "true"})),
                  ("source", frozenset({"factory", "bundle"}))),
    "fortianalyzer": (("protected", frozenset({"1", "true"})),),
    "fortiauthenticator": (),
}

#: Physical port names: hardware, not a naming decision.
_HARDWARE = re.compile(r"^(port|mgmt|ha|wan|lan|internal|dmz)\d+$", re.IGNORECASE)

_FACTORY_FILE = (Path(__file__).resolve().parents[1]
                 / "registry" / "data" / "naming_factory.json")
_factory_cache: dict | None = None


def factory_catalog() -> dict:
    """``{product: {"names": {table: set}, "patterns": {table: [re]}}}``."""
    global _factory_cache
    if _factory_cache is None:
        raw = json.loads(_FACTORY_FILE.read_text(encoding="utf-8"))
        out: dict = {}
        for product, block in raw.items():
            if product.startswith("_") or not isinstance(block, dict):
                continue
            out[product] = {
                "measured_on": block.get("measured_on", ""),
                "names": {t: set(v) for t, v in (block.get("names") or {}).items()},
                "patterns": {t: [re.compile(p) for p in v]
                             for t, v in (block.get("patterns") or {}).items()},
            }
        _factory_cache = out
    return _factory_cache


# ── small helpers ────────────────────────────────────────────────────────────

def object_name(row) -> str | None:
    if not isinstance(row, dict):
        return None
    for k in NAME_KEYS:
        v = row.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return None


def split_name(name: str) -> tuple[list[str], list[str]]:
    """``"pol-root_shop"`` → (["pol", "root", "shop"], ["-", "_"])."""
    parts = _SPLIT.split(name.strip())
    tokens = [p for i, p in enumerate(parts) if i % 2 == 0]
    seps = [p for i, p in enumerate(parts) if i % 2 == 1]
    if tokens and tokens[0] == "":
        tokens, seps = tokens[1:], seps[1:]
    if tokens and tokens[-1] == "":
        tokens, seps = tokens[:-1], seps[:-1]
    return tokens, seps


def case_of(name: str) -> str:
    letters = [c for c in name if c.isalpha()]
    if not letters:
        return "none"
    if all(c.islower() for c in letters):
        return "lower"
    if all(c.isupper() for c in letters):
        return "UPPER"
    return "Mixed"


def factory_reason(product: str, table: str, row: dict, name: str) -> str | None:
    """Why this object is the vendor's, or None when it is the team's."""
    for fld, values in FACTORY_FLAGS.get(product, ()):
        if str(row.get(fld, "")).strip().lower() in values:
            return f"device flag {fld}={row.get(fld)}"
    cat = factory_catalog().get(product) or {}
    if name in (cat.get("names") or {}).get(table, ()):
        return "factory name (measured list)"
    pats = (cat.get("patterns") or {})
    for rx in list(pats.get(table, ())) + list(pats.get("*", ())):
        if rx.search(name):
            return f"factory name pattern {rx.pattern}"
    if "interface" in table and _HARDWARE.match(name):
        return "physical port"
    if product == "fortigate" and table == "system_interface" \
            and str(row.get("type", "")).lower() == "physical":
        return "physical port"
    return None


def field_values(row: dict) -> dict[str, set[str]]:
    """Comparable values of an object's own scalar fields (lower-case).

    A space-separated list (FortiWeb multi-value fields) contributes each
    item; a host name contributes its first label too; a port contributes
    its service word, so ``https`` in a name correlates with ``port=443``."""
    out: dict[str, set[str]] = {}
    for k, v in row.items():
        if k in NAME_KEYS or k.lower() in FREE_TEXT_KEYS or k.startswith(("q_", "_")) \
                or isinstance(v, bool):
            continue
        if not isinstance(v, (str, int, float)):
            continue
        sv = str(v).strip().lower()
        if not sv or len(sv) > 128:
            continue
        vals = {sv}
        if " " in sv:
            vals.update(x for x in sv.split() if x)
        if "." in sv and not sv.replace(".", "").isdigit():
            vals.add(sv.split(".", 1)[0])
        for x in list(vals):
            if x in PORT_WORDS and ("port" in k.lower() or "service" in k.lower()):
                vals.add(PORT_WORDS[x])
        out[k] = vals
    return out


def token_class(field: str, sample: str) -> str:
    """The token a field-correlated position is shown as."""
    f = field.lower()
    if f in ("@adom",):
        return "adom"
    if f in ("@device",):
        return "device"
    if sample in PROTO_WORDS:
        return "proto"
    if "port" in f and sample.isdigit():
        return "port"
    if f in ("vdom", "adom"):
        return "adom"
    if any(w in f for w in ("host", "domain", "fqdn", "sni", "server-name")) or f == "cn":
        return "host"
    if re.match(r"^\d+\.\d+", sample) and any(w in f for w in ("ip", "addr", "subnet", "vip")):
        return "ip"
    return re.sub(r"[^a-z0-9_-]+", "-", f).strip("-") or "field"


# ── inference ────────────────────────────────────────────────────────────────

class _Obj:
    __slots__ = ("name", "tokens", "seps", "fvals", "row")

    def __init__(self, name: str, row: dict, ctx: dict[str, set[str]]):
        self.name = name
        self.row = row
        self.tokens, self.seps = split_name(name)
        self.fvals = field_values(row)
        for k, vals in ctx.items():
            self.fvals.setdefault(k, set()).update(vals)


def _matches(spec: dict, token: str, obj: _Obj) -> bool:
    t = token.lower()
    if spec["kind"] == "lit":
        return t == spec["value"].lower()
    if spec["kind"] == "field":
        return t in obj.fvals.get(spec["field"], ())
    if spec["kind"] == "num":
        return t.isdigit()
    return True


def _describe(tokens: list[str], objs: list[_Obj]) -> dict | None:
    """What one position is across a cluster, or None when it is free."""
    n = len(objs)
    low = [t.lower() for t in tokens]
    # 1) correlated with a field of the same object (or the device context)
    hits: Counter = Counter()
    for t, o in zip(low, objs):
        for k, vals in o.fvals.items():
            if t in vals:
                hits[k] += 1
    if hits:
        # prefer the context, then the field matching most objects
        best = max(hits, key=lambda k: (hits[k], k.startswith("@")))
        if hits[best] / n >= THRESHOLD:
            distinct = set(low)
            # one constant value on every object is a literal unless it is
            # the device context (``root`` = the ADOM, not the team's text)
            if len(distinct) > 1 or best.startswith("@"):
                return {"kind": "field", "field": best,
                        "token": token_class(best, low[0])}
    # 2) literal
    value, cnt = Counter(low).most_common(1)[0]
    if cnt / n >= THRESHOLD and (n >= MIN_CLUSTER or len(objs) == 1):
        original = Counter(t for t in tokens if t.lower() == value).most_common(1)[0][0]
        return {"kind": "lit", "value": original}
    # 3) digits matching no field
    if sum(1 for t in low if t.isdigit()) / n >= THRESHOLD:
        return {"kind": "num", "token": "num"}
    return None


def _render(left: list[dict], middle: bool, right: list[dict], sep: str) -> str:
    def one(s):
        return s["value"] if s["kind"] == "lit" else "{" + s["token"] + "}"
    parts = [one(s) for s in left] + (["{name}"] if middle else []) + [one(s) for s in right]
    return sep.join(parts)


def _infer_cluster(objs: list[_Obj], sep: str) -> dict:
    min_len = min(len(o.tokens) for o in objs)
    max_len = max(len(o.tokens) for o in objs)
    # Right anchors first (suffixes such as the port), never the first token.
    right: list[dict] = []
    j = 1
    while j < min_len:
        spec = _describe([o.tokens[-j] for o in objs], objs)
        if spec is None:
            break
        right.insert(0, spec)
        j += 1
    left: list[dict] = []
    i = 0
    while i < min_len - len(right):
        spec = _describe([o.tokens[i] for o in objs], objs)
        if spec is None:
            break
        left.append(spec)
        i += 1
    fixed = len(left) + len(right)
    middle = max_len > fixed or min_len > fixed
    pattern = _render(left, middle, right, sep)
    conform, exceptions = [], []
    for o in objs:
        why = _check(o, left, middle, right, sep)
        (exceptions.append({"name": o.name, "reason": why}) if why
         else conform.append(o.name))
    return {"pattern": pattern, "left": left, "right": right, "middle": middle,
            "count": len(objs), "conform": conform, "exceptions": exceptions}


def _check(o: _Obj, left, middle, right, sep) -> str | None:
    need = len(left) + len(right) + (1 if middle else 0)
    if len(o.tokens) < need:
        return "fewer parts than the pattern"
    for spec, tok in zip(left, o.tokens):
        if not _matches(spec, tok, o):
            return _why(spec, tok, o)
    for spec, tok in zip(right, o.tokens[len(o.tokens) - len(right):]):
        if not _matches(spec, tok, o):
            return _why(spec, tok, o)
    if o.seps and sep and any(s != sep for s in o.seps):
        other = next(s for s in o.seps if s != sep)
        return f"separator {other!r} instead of {sep!r}"
    return None


def _why(spec: dict, tok: str, o: _Obj) -> str:
    if spec["kind"] == "lit":
        return f"{tok!r} where the convention has {spec['value']!r}"
    if spec["kind"] == "field":
        fld = spec["field"]
        have = sorted(o.fvals.get(fld, ()))
        shown = (have[0] if len(have) == 1 else ", ".join(have[:3])) if have else "(empty)"
        label = fld.lstrip("@")
        return (f"name says {tok!r} but the object's {label} is {shown!r} "
                f"— stale name?")
    return f"{tok!r} is not a number"


def analyse_table(product: str, table: str, rows: list, ctx: dict[str, set[str]]) -> dict:
    """Everything the page shows for one object type on one device."""
    named, factory = [], Counter()
    unnamed = 0
    for r in rows or ():
        if not isinstance(r, dict):
            continue
        name = object_name(r)
        if name is None:
            unnamed += 1
            continue
        why = factory_reason(product, table, r, name)
        if why:
            factory[why] += 1
            continue
        named.append(_Obj(name, r, ctx))
    out = {"table": table, "total": len(rows or ()), "user": len(named),
           "factory": sum(factory.values()), "factory_reasons": dict(factory),
           "unnamed": unnamed, "patterns": [], "main": None, "conform": 0,
           "exceptions": [], "case": None, "separator": None, "status": "ok",
           "names": sorted(o.name for o in named)}
    if not named:
        out["status"] = "factory_only" if factory else ("unnamed" if unnamed else "empty")
        return out
    if sum(1 for o in named if o.name.isdigit()) / len(named) >= THRESHOLD:
        out["status"] = "numeric"
        return out
    sep_count = Counter(s for o in named for s in o.seps)
    sep = sep_count.most_common(1)[0][0] if sep_count else ""
    out["separator"] = sep or None
    out["case"] = Counter(case_of(o.name) for o in named).most_common(1)[0][0]
    if len(named) == 1:
        # one name is not a convention: anything inferred from it would be
        # the name itself or a coincidence (``ADC_Lab_Root_CA`` → {adom})
        out["status"] = "few"
        return out
    single =[o for o in named if len(o.tokens) <= 1]
    if len(single) / len(named) >= THRESHOLD:
        out["status"] = "single_word" if len(named) > 1 else "few"
        out["main"] = "{name}"
        out["conform"] = len(single)
        out["patterns"] = [{"pattern": "{name}", "count": len(single),
                            "conform": [o.name for o in single], "exceptions": []}]
        out["exceptions"] = [{"name": o.name, "reason": "has parts where the others are one word"}
                             for o in named if len(o.tokens) > 1]
        return out
    clusters: dict[str, list[_Obj]] = defaultdict(list)
    for o in named:
        clusters[o.tokens[0].lower() if len(o.tokens) > 1 else ""].append(o)
    ordered = sorted(clusters.items(), key=lambda kv: (-len(kv[1]), kv[0]))
    loose: list[_Obj] = []
    for key, members in ordered:
        if key and (len(members) >= MIN_CLUSTER or len(named) == 1):
            out["patterns"].append(_infer_cluster(members, sep))
        else:
            loose.extend(members)
    if out["patterns"]:
        main = out["patterns"][0]
        out["main"] = main["pattern"]
        out["conform"] = len(main["conform"])
        out["exceptions"] = list(main["exceptions"])
        for v in out["patterns"][1:]:
            out["exceptions"] += [{"name": n, "reason": f"variant {v['pattern']}"}
                                  for n in v["conform"]]
            out["exceptions"] += v["exceptions"]
    for o in loose:
        reason = ("one word, no parts" if len(o.tokens) <= 1
                  else f"prefix {o.tokens[0]!r} used by no other object")
        out["exceptions"].append({"name": o.name, "reason": reason})
    if not out["patterns"]:
        out["status"] = "no_convention"
    for p in out["patterns"]:
        p.pop("left", None), p.pop("right", None), p.pop("middle", None)
    return out


# ── whole device / fleet ─────────────────────────────────────────────────────

def context_for(device: str, tree: dict) -> dict[str, set[str]]:
    """Device-level values a name may embed: its ADOM/VDOM names, its name."""
    adoms = {"root"}
    for sec in (tree.get("sections") or {}).values():
        for t in ("system_vdom", "dvmdb_adom", "vdom", "system_adom"):
            for r in sec.get(t, ()) if isinstance(sec, dict) else ():
                n = object_name(r)
                if n:
                    adoms.add(n.lower())
    dev = {device.lower()} if device else set()
    return {"@adom": adoms, "@device": dev}


def free_part(name: str, pattern: str | None) -> str | None:
    """The ``{name}`` part of ``name`` under ``pattern`` (None if no match)."""
    rx = pattern_regex(pattern, capture=True) if pattern else None
    m = rx.match(name) if rx else None
    return m.group("name").lower() if m and "name" in m.groupdict() else None


def linked_names(tables: list[dict], tree_rows: dict[str, list]) -> None:
    """Annotate each table with the object types sharing its ``{name}``.

    ``pol-root-shop`` → ``vs-root-shop`` → ``pool-root-shop`` is ONE site
    identifier carried across the objects of a policy — the scheme's
    ``{name}``. Counted only through real references (a field of the object
    naming the other object)."""
    by_name: dict[str, tuple[str, str]] = {}
    mains = {t["table"]: t.get("main") for t in tables}
    for t in tables:
        for n in t.get("names", ()):
            fp = free_part(n, mains.get(t["table"]))
            if fp:
                by_name.setdefault(n.lower(), (t["table"], fp))
    for t in tables:
        counts: dict[str, list[int]] = defaultdict(lambda: [0, 0])
        main = t.get("main")
        if not main or "{name}" not in main:
            t["linked"] = []
            continue
        for r in tree_rows.get(t["table"], ()):
            n = object_name(r)
            fp = free_part(n, main) if n else None
            if not fp:
                continue
            seen = set()
            for k, vals in field_values(r).items():
                for v in vals:
                    hit = by_name.get(v)
                    if not hit or hit[0] == t["table"] or hit[0] in seen:
                        continue
                    seen.add(hit[0])
                    counts[hit[0]][1] += 1
                    if hit[1] == fp:
                        counts[hit[0]][0] += 1
        t["linked"] = sorted(({"table": k, "matched": v[0], "total": v[1]}
                              for k, v in counts.items() if v[0]),
                             key=lambda x: -x["matched"])


def analyse_device(product: str, device: str, tree: dict,
                   labels: dict[str, str] | None = None) -> dict:
    sections = tree.get("sections") or {}
    ctx = context_for(device, tree)
    tables, rows_by_table = [], {}
    for sec, tabs in sections.items():
        if not isinstance(tabs, dict):
            continue
        for table, rows in tabs.items():
            if not isinstance(rows, list):
                continue
            rows_by_table[table] = rows
            t = analyse_table(product, table, rows, ctx)
            if t["status"] in ("empty", "unnamed"):
                continue
            t["section"] = sec
            t["label"] = (labels or {}).get(table) or humanize(table)
            tables.append(t)
    linked_names(tables, rows_by_table)
    tables.sort(key=lambda t: (t["status"] == "factory_only", t["section"], t["label"]))
    return {"device": device, "product": product,
            "generated_at": tree.get("generated_at"),
            "tables": tables,
            "user_objects": sum(t["user"] for t in tables),
            "factory_objects": sum(t["factory"] for t in tables)}


def object_types(sweep: dict[str, str], trees: list[dict],
                 kinds: dict[str, str] | None = None) -> dict[str, dict]:
    """Every object type the naming scheme lists for a product.

    ``sweep`` is ``{table: section}`` of what the product's configuration
    sweep reads (``device_sync.sweep_tables``); ``trees`` the configuration
    trees SATOM holds for its devices. The sweep keeps only tables that
    returned rows, so a table is judged by what the trees show:

    * named rows on some device → an object type (``seen``); ``numeric``
      when every name is a number (Discovery says "keyed by number");
    * rows but never a name → a settings block, not an object type → left
      out;
    * in the sweep but empty on every device → judged by ``kinds``, the shape
      the API library measured on the devices' builds
      (``device_sync.table_kinds``): a ``singleton`` is a settings block →
      left out; a ``table`` or an unmeasured one is listed (``seen`` False):
      the object type a device WILL hold once someone creates one.

    Every type Discovery shows with team objects is in the result, so the
    two tabs of the Naming page list the same object types. ``shape`` is the
    measured kind (``"table"``/``"singleton"``) or ``""`` when no build
    measured it.

    Returns ``{table: {"section": str, "seen": bool, "numeric": bool,
    "shape": str}}``."""
    kinds = kinds or {}
    named: set[str] = set()
    worded: set[str] = set()
    nameless: set[str] = set()
    section: dict[str, str] = {}
    for tree in trees:
        for sec, tabs in ((tree or {}).get("sections") or {}).items():
            if not isinstance(tabs, dict):
                continue
            for table, rows in tabs.items():
                if not isinstance(rows, list) or not rows:
                    continue
                section.setdefault(table, sec)
                names = [n for n in (object_name(r) for r in rows) if n]
                if names:
                    named.add(table)
                    if any(not n.isdigit() for n in names):
                        worded.add(table)
                else:
                    nameless.add(table)
    out: dict[str, dict] = {}
    for table in set(sweep) | named:
        if table in nameless and table not in named:
            continue
        if table not in named and kinds.get(table) == "singleton":
            continue
        out[table] = {"section": section.get(table) or sweep.get(table) or "Other",
                      "seen": table in named,
                      "numeric": table in named and table not in worded,
                      "shape": kinds.get(table) or ""}
    return out


def fleet_view(analyses: list[dict]) -> list[dict]:
    """Per object type across devices: each device's main pattern + consensus."""
    rows: dict[str, dict] = {}
    for a in analyses:
        for t in a["tables"]:
            if not t.get("main"):
                continue
            r = rows.setdefault(t["table"], {"table": t["table"], "label": t["label"],
                                             "section": t["section"], "devices": []})
            r["devices"].append({"device": a["device"], "main": t["main"],
                                 "conform": t["conform"], "user": t["user"]})
    out = []
    for r in rows.values():
        c = Counter(d["main"] for d in r["devices"])
        r["consensus"], n = c.most_common(1)[0]
        # one device cannot agree with anyone: "all agree" would be vacuous
        r["single"] = len(r["devices"]) == 1
        r["agree"] = n == len(r["devices"]) and not r["single"]
        out.append(r)
    return sorted(out, key=lambda r: (r["section"], r["label"]))


# ── patterns as checks ───────────────────────────────────────────────────────

def pattern_tokens(pattern: str) -> set[str]:
    return set(_TOKEN_RE.findall(pattern or ""))


def pattern_regex(pattern: str, *, capture: bool = False, free=()):
    """A full-match, case-insensitive regex for a (discovered or adopted) pattern.

    *free* names tokens that match free text like ``{name}`` does: on a
    catalog element ``{host}`` and the naming variables are filled in from
    the site (``blabla_example_com``), not one separator-free part."""
    if not pattern:
        return None
    free = set(free or ())
    out, pos, seen = [], 0, set()
    for m in _TOKEN_RE.finditer(pattern):
        out.append(re.escape(pattern[pos:m.start()]))
        tok = m.group(1)
        if tok == "name" or tok in free:
            body = ".+?"
        elif tok in ("port", "num"):
            body = r"\d+"
        elif tok == "proto":
            body = "(?:" + "|".join(sorted(PROTO_WORDS, key=len, reverse=True)) + ")"
        else:
            body = r"[^\-_.\s]+"
        if capture and tok not in seen and re.match(r"^[a-z_]\w*$", tok):
            out.append(f"(?P<{tok}>{body})")
            seen.add(tok)
        else:
            out.append(f"(?:{body})")
        pos = m.end()
    out.append(re.escape(pattern[pos:]))
    return re.compile("^" + "".join(out) + "$", re.IGNORECASE)


def conformance(pattern: str, names: list[str], *, free=()) -> dict:
    rx = pattern_regex(pattern, free=free)
    if rx is None:
        return {"pattern": pattern, "conform": 0, "total": len(names), "misses": []}
    misses = [n for n in names if not rx.match(n)]
    return {"pattern": pattern, "conform": len(names) - len(misses),
            "total": len(names), "misses": misses}


def scheme_compatible(pattern: str) -> tuple[bool, str]:
    """Can this pattern be written into the Naming scheme as it is?

    The scheme fills in the site tokens (``naming.SITE_TOKENS``) and the
    product's variables (``naming.render_names``); a Discovery token such as
    ``{adom}`` or ``{num}`` would reach a device as literal text. Checked
    here without the variables: a discovered pattern never carries one."""
    from .naming import SITE_TOKENS
    extra = pattern_tokens(pattern) - set(SITE_TOKENS)
    if extra:
        return False, ("the naming scheme only fills in "
                       + ", ".join("{" + t + "}" for t in SITE_TOKENS) + "; "
                       + ", ".join("{" + t + "}" for t in sorted(extra))
                       + " would be written literally")
    if not ({"name", "host"} & pattern_tokens(pattern)):
        return False, "the pattern has no {name} or {host} part"
    return True, ""


def humanize(table: str) -> str:
    s = table.replace("_", " ").strip()
    return s[:1].upper() + s[1:]


def load_tree(path) -> dict | None:
    p = Path(path)
    if not p.is_file():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def to_csv_rows(analysis: dict) -> list[list]:
    rows = [["device", "section", "object type", "pattern", "conform", "user objects",
             "factory objects", "exception", "reason"]]
    for t in analysis["tables"]:
        base = [analysis["device"], t["section"], t["label"], t.get("main") or "",
                t["conform"], t["user"], t["factory"]]
        if t["exceptions"]:
            for e in t["exceptions"]:
                rows.append(base + [e["name"], e["reason"]])
        else:
            rows.append(base + ["", ""])
    return rows
