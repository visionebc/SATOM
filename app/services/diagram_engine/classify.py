"""Semantic classifier: gives every unclassified element a ``category`` /
``symbol`` and extracts network semantics (IP, CIDR, VLAN, ASN, hostname, zone)
into ``metadata``. Deterministic, never invents: an address is only recorded
when :mod:`ipaddress` accepts it, a VLAN only within 1..4094.

Evidence, strongest first (confidence): source hints 0.95 (draw.io stencil
globs, Visio master globs, SATOM kinds), label text regexes 0.8, shape geometry
0.7, connector context 0.65. Operator decisions are sacred: an element with
``metadata.category_locked`` is never touched, and a category with confidence
>= 0.6 is kept. Categories and symbols come from the loaded flat libraries (data;
``color``/``iso3d`` style variants are reachable through each symbol's ``variants``),
the only built-in knowledge being the geometry rules below.

Standalone: stdlib + sibling modules.
"""
from __future__ import annotations

import fnmatch
import ipaddress
import re

from . import model, symbols as symlib

CONF_HINT, CONF_TEXT, CONF_SHAPE, CONF_CONTEXT = 0.95, 0.8, 0.7, 0.65
STRONG = 0.8
MAX_TEXT = 400          # characters of a label that are matched (bounds regex work)

# shape geometry -> category (resolved to a symbol through the libraries)
SHAPE_RULES = {"diamond": "flow.decision", "parallelogram": "flow.io", "cylinder": "infra.database",
               "document": "flow.document", "actor": "uml.actor"}
TERMINATOR_SHAPES = ("terminator", "ellipse", "pill", "round")
TERMINATOR_RE = re.compile(r"\b(start|end|begin|stop|finish)\b", re.I)
YES = {"yes", "y", "true"}
NO = {"no", "n", "false"}
ZONE_CATEGORIES = {"security.zone", "security.trust_boundary", "network.zone", "network.dmz"}

_IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?(?![\w])(?!\.\d)")
_IPV6_RE = re.compile(r"(?<![\w:])[0-9A-Fa-f:]{2,45}(?:/\d{1,3})?(?![\w:])")
_VLAN_RE = re.compile(r"\bvlan[\s_-]*(?:id)?[\s:=#]*(\d{1,4})\b", re.I)
_ASN_RE = re.compile(r"\b(?:AS[\s-]?|ASN[\s:=-]*)(\d{1,10})\b")
_FQDN_RE = re.compile(r"(?<![\w.@/-])[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.[A-Za-z]{2,24}(?![\w-])")
_HYPHEN_HOST_RE = re.compile(r"(?<![\w.-])[A-Za-z][A-Za-z0-9]*(?:-[A-Za-z0-9]+)+(?![\w-])(?!\.[A-Za-z0-9])")
_PREFIX_HOST_RE = re.compile(r"(?<![\w.-])(?:fw|sw|rtr|srv|db|lb|ap|vm|pve|prt|dc|core|gw|ns|mx)\d{1,4}(?![\w-])", re.I)
_ZONE_RE = re.compile(r"\b(dmz|wan|lan|inside|outside)\b", re.I)
_PROTO_RE = re.compile(r"\b(bgp|ospf|eigrp|is-?is)\b", re.I)
_FILE_TLDS = {"js", "py", "md", "txt", "json", "yml", "yaml", "sh", "css", "html", "php", "png", "jpg", "svg", "pdf", "exe", "log", "conf", "cfg"}


# ------------------------------------------------------------ semantics

def _ips(text: str) -> tuple[list, list]:
    """``(addresses, cidrs)`` validated by ``ipaddress``, in order of appearance."""
    ips, cidrs = [], []

    def take(tok):
        try:
            if "/" in tok:
                net = ipaddress.ip_network(tok, strict=False)
                c = str(net)
                if c not in cidrs:
                    cidrs.append(c)
                host = tok.split("/")[0]
                if ipaddress.ip_address(host) != net.network_address and host not in ips:
                    ips.append(str(ipaddress.ip_address(host)))
            else:
                a = str(ipaddress.ip_address(tok))
                if a not in ips:
                    ips.append(a)
        except ValueError:
            pass
    for m in _IPV4_RE.finditer(text):
        take(m.group(0))
    for m in _IPV6_RE.finditer(text):
        tok = m.group(0)
        if tok.count(":") >= 2:
            take(tok)
    return ips, cidrs


def _hostnames(text: str, skip: list) -> list:
    stripped = text
    for s in skip:
        stripped = stripped.replace(s, " ")
    found = []
    for rx in (_HYPHEN_HOST_RE, _FQDN_RE, _PREFIX_HOST_RE):
        for m in rx.finditer(stripped):
            tok = m.group(0)
            low = tok.lower()
            if low.startswith(("vlan-", "as-", "ipv4", "ipv6")):
                continue
            if rx is _FQDN_RE and low.rsplit(".", 1)[-1] in _FILE_TLDS:
                continue
            if rx is _HYPHEN_HOST_RE and not any(ch.isdigit() for ch in tok):
                continue
            if tok not in found:
                found.append(tok)
    return found


def extract_semantics(text: str) -> dict:
    """Facts readable from a label; only validated values, never guesses."""
    text = (text or "")[:MAX_TEXT * 2]
    out: dict = {}
    ips, cidrs = _ips(text)
    if ips:
        out["ip"] = ", ".join(ips)
    if cidrs:
        out["cidr"] = ", ".join(cidrs)
    vlans = []
    for m in _VLAN_RE.finditer(text):
        v = int(m.group(1))
        if 1 <= v <= 4094 and v not in vlans:
            vlans.append(v)
    if vlans:
        out["vlan"] = vlans[0] if len(vlans) == 1 else ", ".join(map(str, vlans))
    asns = []
    for m in _ASN_RE.finditer(text):
        v = int(m.group(1))
        if 1 <= v <= 4294967295 and v not in asns:
            asns.append(v)
    if asns:
        out["asn"] = asns[0] if len(asns) == 1 else ", ".join("AS%d" % a for a in asns)
    host = _hostnames(text, ips + cidrs)
    if host:
        out["hostname"] = ", ".join(host[:4])
    zm = _ZONE_RE.search(text)
    if zm and (zm.group(1).lower() in ("dmz", "wan", "lan") or len(text.strip()) <= 40):
        out["zone"] = zm.group(1).lower()
    return out


# ------------------------------------------------------------- indexing

def _lib_list(libraries) -> list:
    if libraries is None:
        libraries = symlib.libraries()
    if isinstance(libraries, dict):
        libraries = [libraries[k] for k in sorted(libraries)]
    return list(libraries)


def _norm_visio(name: str) -> str:
    n = re.sub(r"\.\d+$", "", name.strip().lower())
    return re.sub(r"[\s_]+", " ", n)


class _Index:
    def __init__(self, libraries):
        self.drawio, self.visio, self.satom, self.text = [], [], {}, []
        self.by_category: dict = {}
        self.sym: dict = {}
        for lib in _lib_list(libraries):
            if lib.get("variant", "flat") != "flat":
                continue        # colour / 3D variants share the flat concepts; classification stays on flat icons
            for s in lib["symbols"]:
                ref = "%s/%s" % (lib["id"], s["id"])
                self.sym[ref] = s
                if s["category"] not in self.by_category or ref < self.by_category[s["category"]]:
                    self.by_category[s["category"]] = ref      # library order must not matter
                al = s.get("aliases", {})
                for g in al.get("drawio", []):
                    self.drawio.append((g.lower(), ref))
                for g in al.get("visio", []):
                    self.visio.append((re.sub(r"[\s_]+", " ", g.lower()), ref))
                for k in al.get("satom", []):
                    self.satom.setdefault(k.lower(), []).append(ref)
                for p in al.get("text", []):
                    try:
                        self.text.append((re.compile(p, re.I), ref))
                    except re.error:
                        continue

    def cat(self, ref):
        return self.sym[ref]["category"]


def _spec(pattern: str) -> int:
    return len(re.sub(r"[*?\[\]]", "", pattern))


def _mask_ipv6(text: str) -> str:
    """Blank out IPv6 literals so hex groups ("db8") are never read as words."""
    def sub(m):
        tok = m.group(0)
        if tok.count(":") >= 2:
            try:
                ipaddress.ip_network(tok, strict=False)
                return " "
            except ValueError:
                pass
        return tok
    return _IPV6_RE.sub(sub, text)


def _drawio_name(el) -> str:
    md = el.get("metadata", {})
    name = md.get("drawio_shape")
    if isinstance(name, str) and name:
        return name.strip().lower()
    nat = el.get("native") or {}
    if nat.get("format") == "drawio":
        m = re.search(r"(?:^|;)shape=([^;]+)", nat.get("style", ""))
        if m:
            return m.group(1).strip().lower()
    return ""


def _candidates(el, idx: _Index, edge_labels: list) -> list:
    """``[(confidence, specificity, ref, source)]`` sorted best first."""
    cands = []
    md = el.get("metadata", {})
    dn = _drawio_name(el)
    if dn:
        for g, ref in idx.drawio:
            if fnmatch.fnmatchcase(dn, g):
                cands.append((CONF_HINT, _spec(g), ref, "hint"))
    vm = md.get("visio_master")
    if isinstance(vm, str) and vm.strip():
        n = _norm_visio(vm)
        for g, ref in idx.visio:
            if fnmatch.fnmatchcase(n, g):
                cands.append((CONF_HINT, _spec(g), ref, "hint"))
    st = md.get("satom_type")
    if isinstance(st, str) and st.strip():
        for ref in idx.satom.get(st.strip().lower(), []):
            cands.append((CONF_HINT, 100, ref, "hint"))
    texts = [t for t in (el.get("name"), el.get("text"), md.get("svg_id"), md.get("svg_class")) if isinstance(t, str) and t.strip()]
    for t in texts:
        t = _mask_ipv6(t[:MAX_TEXT])
        for rx, ref in idx.text:
            m = rx.search(t)
            if m and m.group(0).strip() and not _geometry_contradicts(el.get("shape"), idx.sym.get(ref)):
                cands.append((CONF_TEXT, len(m.group(0).strip()), ref, "text"))
    shape = el.get("shape")
    joined = " ".join(texts)
    cat = SHAPE_RULES.get(shape)
    if cat is None and shape in TERMINATOR_SHAPES and TERMINATOR_RE.search(joined[:MAX_TEXT]):
        cat = "flow.terminator"
    if shape == "terminator":
        cat = "flow.terminator"
    if cat:
        cands.append((CONF_SHAPE, 0, idx.by_category.get(cat) or cat, "shape"))
    elif any(_label_kind(lab) in ("yes", "no") for lab in edge_labels) and edge_labels:
        cands.append((CONF_CONTEXT, 0, idx.by_category.get("flow.decision") or "flow.decision", "context"))
    # best first; ties broken by library/symbol reference for determinism
    cands.sort(key=lambda c: (-c[0], -c[1], c[2]))
    return cands


#: Flowchart symbols whose meaning IS their outline: a label alone ("Read
#: request", "Valid?") must not turn an element of another geometry into one.
GEOMETRIC_FLOW = {"parallelogram", "diamond", "trapezoid", "document"}
#: Element shapes that are a definite geometry (as opposed to path/polygon/symbol).
DEFINITE_SHAPES = {"rect", "round", "pill", "ellipse", "diamond", "hexagon", "parallelogram",
                   "trapezoid", "triangle", "cylinder", "terminator", "process", "document"}


def _geometry_contradicts(shape, sym) -> bool:
    if not sym or not str(sym.get("category", "")).startswith("flow."):
        return False
    want = sym.get("shape")
    return want in GEOMETRIC_FLOW and shape in DEFINITE_SHAPES and shape != want


def _label_kind(label: str) -> str:
    n = re.sub(r"[^\w]+", "", (label or "").strip().lower())
    return "yes" if n in YES else "no" if n in NO else ""


def _category_of(ref: str, idx: _Index) -> str:
    return idx.sym[ref]["category"] if ref in idx.sym else ref


# ------------------------------------------------------------ connectors

def _classify_connector(c: dict, els: dict, rep: dict) -> None:
    labels = [c.get("label", "")] + [l.get("text", "") for l in c.get("labels", [])]
    text = " ".join(t for t in labels if t)[:MAX_TEXT]
    md = c.setdefault("metadata", {})
    kind, by = c.get("kind", ""), ""
    sem = extract_semantics(text)
    for k in ("ip", "cidr", "vlan", "asn"):
        if k in sem:
            md.setdefault(k, sem[k])
    pm = _PROTO_RE.search(text)
    proto = pm.group(1).lower().replace("-", "") if pm else ""
    if proto:
        md.setdefault("routing_protocol", proto)
    if not kind:
        lk = _label_kind(c.get("label", "") or (c.get("labels") or [{}])[0].get("text", ""))
        low = text.lower()
        if lk:
            kind, by = lk, "text"
        elif proto:
            kind, by = proto, "text"
        elif re.search(r"\b(vpn|ipsec|tunnel|wireguard|gre)\b", low):
            kind, by = "vpn", "text"
        elif re.search(r"\b(wi-?fi|wireless|wlan)\b", low):
            kind, by = "wireless", "text"
        elif c.get("style", {}).get("dashed"):
            ends = [els.get(c.get("source", "")), els.get(c.get("target", ""))]
            if all(e is not None and (e.get("category") in ZONE_CATEGORIES or e.get("metadata", {}).get("zone")) for e in ends):
                kind, by = "data_flow", "context"
        if kind:
            c["kind"] = kind
            md.setdefault("classified_by", by)
            rep["connector_kinds"][kind] = rep["connector_kinds"].get(kind, 0) + 1


# ------------------------------------------------------------- main door

def classify(doc: dict, libraries=None) -> tuple[dict, dict]:
    """``(classified copy, report)``; the input document is not modified.

    *libraries*: dict ``{id: lib}`` or iterable of libraries as returned by
    :mod:`symbols` (default: all registered). The report lists counts by
    family and by evidence, ``unknown`` element ids, ``conflicts`` (strong
    candidates that disagree) and the locked elements it left alone.
    """
    doc = model.deep_copy(doc)
    idx = _Index(libraries)
    rep = {"classified": 0, "by_source": {}, "by_family": {}, "unknown": [], "conflicts": [],
           "locked": [], "connector_kinds": {}, "extracted": {}}
    for page in doc.get("pages", []):
        els = {e["id"]: e for e in page.get("elements", [])}
        out_labels: dict = {}
        for c in page.get("connectors", []):
            labs = [c.get("label", "")] + [l.get("text", "") for l in c.get("labels", [])]
            if c.get("source") in els:
                out_labels.setdefault(c["source"], []).extend(t for t in labs if t)
        for el in page.get("elements", []):
            md = el.setdefault("metadata", {})
            locked = md.get("category_locked") in (True, "true", "True", 1)
            sem = extract_semantics(" ".join(t for t in (el.get("name"), el.get("text")) if t))
            for k, v in sem.items():
                if k not in md:
                    md[k] = v
                    rep["extracted"][k] = rep["extracted"].get(k, 0) + 1
            if locked:
                rep["locked"].append(el["id"])
                continue
            if el.get("kind") == "text":
                continue
            if el.get("category") and el.get("confidence", 1.0) >= model.LOW_CONFIDENCE:
                continue
            cands = _candidates(el, idx, out_labels.get(el["id"], []))
            if not cands:
                continue
            conf, _spec_len, ref, source = cands[0]
            cat = _category_of(ref, idx)
            strong = [c for c in cands if c[0] >= STRONG]
            clash = [c for c in strong[1:] if _category_of(c[2], idx) != cat and (c[3] != strong[0][3] or c[1] == strong[0][1])]
            if clash:
                seen, listed = set(), []
                for c in [strong[0]] + clash:
                    k = (_category_of(c[2], idx), c[3])
                    if k not in seen:
                        seen.add(k)
                        listed.append({"category": k[0], "symbol": c[2] if c[2] in idx.sym else "",
                                       "source": c[3], "confidence": c[0]})
                rep["conflicts"].append({"element": el["id"], "chosen": cat, "candidates": listed[:4]})
            el["category"] = cat
            el["symbol"] = ref if ref in idx.sym else ""
            el["confidence"] = conf
            md["classified_by"] = source
            rep["classified"] += 1
            rep["by_source"][source] = rep["by_source"].get(source, 0) + 1
        for c in page.get("connectors", []):
            _classify_connector(c, els, rep)
        for el in page.get("elements", []):
            fam = (el.get("category") or "").split(".")[0]
            if fam:
                rep["by_family"][fam] = rep["by_family"].get(fam, 0) + 1
            elif el.get("kind") != "text":
                rep["unknown"].append(el["id"])
    rep["by_family"] = dict(sorted(rep["by_family"].items()))
    rep["by_source"] = dict(sorted(rep["by_source"].items()))
    rep["connector_kinds"] = dict(sorted(rep["connector_kinds"].items()))
    rep["extracted"] = dict(sorted(rep["extracted"].items()))
    return doc, rep
