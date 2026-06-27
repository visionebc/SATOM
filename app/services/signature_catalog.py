"""Read the live signature DATABASE off a FortiWeb — the category tree the
signature picker browses, plus every individual signature and its description.

Ported from the desktop ``app/services/signature_catalog.py`` (Qt-free logic).
FortiWeb's signature editor is a tree: **main class** (Cross Site Scripting, SQL
Injection, Generic Attacks...) -> **sub-class** (OS Command Injection, LDAP
Injection...) -> individual signature ids. Two NON-cmdb ``waf`` REST endpoints
expose it (verified live on fw1 7.6.8, and named in the desktop registry):

* ``signature_dict``            -> GET /api/v2.0/waf/signature.advanced.dictionaries
  ?mkey=<set>                     the top two levels (main class + sub-class) BY NAME.
* ``signature_advanced_detail`` -> GET /api/v2.0/waf/signature.advanced.details
  ?mkey=<set>&main_class_id=<main>&sub_class_id=<sub>
                                  every individual signature of one sub-class,
                                  with its id + description.

SCALABLE: the whole tree comes from the box's own dictionary, so a new firmware /
new categories / new signatures appear automatically — nothing is hardcoded.
(Individual signatures are not REST-enumerable except through the details call
above, so the picker either assembles an id from a sub-class prefix + a number or
the operator pastes the exact id from the attack log.)

Pure + duck-typed: the readers need a client exposing ``api_call(method, path)``
that returns an httpx-style response with ``.json()`` (the web ``FortiWebClient``).
The parse / id helpers are network-free. READ-ONLY: only GET requests are issued.

Web-port note: unlike the desktop (which swallowed every error and returned ``[]``
for an always-on UI), the critical reads here LET EXCEPTIONS PROPAGATE so the
Flask view can wrap the call and flash a real error instead of silently caching an
empty database. Per-sub-class detail reads stay best-effort so one flaky sub-class
never aborts a long sync.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator
from urllib.parse import urlencode

# REST paths (FortiWeb v2.0 API). signature.advanced.* live under /waf, NOT /cmdb.
API_VERSION = "v2.0"
SIG_DICT_PATH = f"/api/{API_VERSION}/waf/signature.advanced.dictionaries"
SIG_DETAIL_PATH = f"/api/{API_VERSION}/waf/signature.advanced.details"
SIG_SET_PATH = f"/api/{API_VERSION}/cmdb/waf/signature"


def _json(client: Any, path: str) -> Any:
    """GET ``path`` through the web FortiWebClient and decode the JSON body."""
    return client.api_call("GET", path).json()


def _unwrap(raw: Any) -> list:
    """The row list out of a FortiWeb ``{"results": [...]}`` envelope (or [])."""
    rows = raw.get("results", raw) if isinstance(raw, dict) else raw
    return rows if isinstance(rows, list) else []


# --------------------------------------------------------------------------- #
#  The category tree (main class -> sub-class), read from the dictionary         #
# --------------------------------------------------------------------------- #
@dataclass
class SigNode:
    """One node of the signature dictionary tree (a main class or a sub-class)."""

    name: str
    main_id: str
    sub_id: str
    type: int                                   # 1 = main class, 2 = sub-class
    children: list["SigNode"] = field(default_factory=list)

    @property
    def is_main(self) -> bool:
        return self.type == 1

    @property
    def node_id(self) -> str:
        """The id this node represents (main_id for a main class, else sub_id)."""
        return self.main_id if self.is_main else self.sub_id


def _node(d: dict) -> SigNode:
    return SigNode(
        name=str(d.get("name") or ""),
        main_id=str(d.get("main_id") or ""),
        sub_id=str(d.get("sub_id") or ""),
        type=int(d.get("type") or 0),
        children=[_node(c) for c in (d.get("children") or []) if isinstance(c, dict)],
    )


def parse_signature_catalog(rows: Any) -> list[SigNode]:
    """Normalise the dictionary ``results`` into a list of main-class :class:`SigNode`."""
    rows = rows.get("results", rows) if isinstance(rows, dict) else rows
    return [_node(d) for d in rows if isinstance(d, dict)] if isinstance(rows, list) else []


def read_signature_catalog(client: Any, signature_set: str) -> list[SigNode]:
    """The live signature category tree for ``signature_set``.

    Raises on a transport / HTTP failure (the Flask view wraps + flashes it);
    returns ``[]`` only when no signature set was supplied."""
    if not signature_set:
        return []
    path = f"{SIG_DICT_PATH}?{urlencode({'mkey': signature_set})}"
    return parse_signature_catalog(_json(client, path))


def _digits(s: Any) -> str:
    return "".join(ch for ch in str(s) if ch.isdigit()).rjust(9, "0")[:9]


def signature_prefix(main_id: str, sub_id: str) -> str:
    """The 6-digit prefix shared by a sub-class's signatures = the MORE SPECIFIC of
    its ``(main_id, sub_id)``.

    Verified live on fw1 7.6.8: a main class that is its own single sub-class carries
    ``sub_id='000000000'`` (XSS: main ``010000000`` -> prefix ``010000`` -> signature
    #1 is ``010000001``), while a real sub-class carries the specific ``sub_id``
    (Generic Attacks > OS Command Injection ``050010000`` -> prefix ``050010``). The
    more-specific id is the lexicographically larger one, so ``max`` picks it."""
    return max(_digits(main_id), _digits(sub_id))[:6]


def signature_id_for(main_id: str, sub_id: str, number: int) -> str:
    """Assemble an individual signature id = sub-class prefix + a 3-digit number.
    e.g. XSS ``(010000000, 000000000, 1)`` -> ``'010000001'``; Generic/OS Command
    ``(050000000, 050010000, 63)`` -> ``'050010063'``."""
    return f"{signature_prefix(main_id, sub_id)}{int(number):03d}"


def iter_subclasses(catalog: list[SigNode]) -> Iterator[tuple[SigNode, SigNode]]:
    """Yield ``(main_class, sub_class)`` for every sub-class — what the picker tree /
    sync walks (a main with no children is treated as its own leaf)."""
    for m in catalog:
        for s in (m.children or [m]):
            yield m, s


# --------------------------------------------------------------------------- #
#  Individual signatures (id + DESCRIPTION) — the real per-signature data        #
# --------------------------------------------------------------------------- #
@dataclass
class Signature:
    """One individual FortiWeb signature (e.g. 010000001 with its description)."""

    id: str
    desc: str = ""
    status: int = 1                  # 1 = enabled in this set
    has_filter: bool = False         # already carries a per-signature exception
    main_id: str = ""
    sub_id: str = ""
    main_name: str = ""
    sub_name: str = ""


def read_subclass_signatures(client: Any, signature_set: str, main_id: str,
                             sub_id: str) -> list[Signature]:
    """The individual signatures of one sub-class.

    Best-effort: returns ``[]`` on any failure so a single flaky sub-class never
    aborts a full sync (matches the desktop)."""
    if not signature_set:
        return []
    path = f"{SIG_DETAIL_PATH}?" + urlencode({
        "mkey": signature_set, "main_class_id": main_id, "sub_class_id": sub_id})
    try:
        raw = _json(client, path)
    except Exception:  # noqa: BLE001 — best-effort per sub-class read
        return []
    out: list[Signature] = []
    for d in _unwrap(raw):
        if not isinstance(d, dict):
            continue
        sid = str(d.get("id") or "").strip()
        if not sid:
            continue
        out.append(Signature(
            id=sid, desc=str(d.get("desc") or "").strip(),
            status=int(d.get("status") or 0), has_filter=bool(d.get("has_filter")),
            main_id=main_id, sub_id=sub_id))
    return out


def pick_signature_set(client: Any) -> str:
    """The name of a signature set to use as the read handle.

    The dictionary / details endpoints expose the box-global signature DB, but
    still want a signature-set ``mkey`` as a handle; any set works, so use the
    first one configured on the device (mirrors the desktop's
    ``client.get_raw_logical('signature')``). Raises on a transport failure."""
    for d in _unwrap(_json(client, SIG_SET_PATH)):
        if isinstance(d, dict) and d.get("name"):
            return str(d["name"])
    return ""


@dataclass
class SignatureDB:
    """The full signature database (all categories' individual signatures + descs)."""

    firmware: str
    generated_at: str
    signature_set: str = ""
    signatures: list[Signature] = field(default_factory=list)

    @property
    def subclass_count(self) -> int:
        return len({(s.main_id, s.sub_id) for s in self.signatures})

    def for_subclass(self, main_id: str, sub_id: str) -> list[Signature]:
        return [s for s in self.signatures
                if s.main_id == main_id and s.sub_id == sub_id]

    def get(self, signature_id: str) -> Signature | None:
        return next((s for s in self.signatures if s.id == signature_id), None)

    def search(self, needle: str, limit: int = 400) -> list[Signature]:
        n = needle.strip().lower()
        if not n:
            return []
        hits = [s for s in self.signatures
                if n in s.id or n in s.desc.lower()
                or n in s.sub_name.lower() or n in s.main_name.lower()]
        return hits[:limit]


def sync_signature_database(
    client: Any, signature_set: str, *, firmware: str = "",
    progress: Callable[[str, int], None] | None = None,
) -> SignatureDB:
    """Walk the dictionary + every sub-class -> the full :class:`SignatureDB`.

    ``progress(label, count_so_far)`` is called per sub-class (optional, for a UI
    bar). READ-ONLY: only GETs are issued. The dictionary read raises on a dead
    device (the view flashes it); per-sub-class reads are best-effort."""
    catalog = read_signature_catalog(client, signature_set)
    sigs: list[Signature] = []
    for m, s in iter_subclasses(catalog):
        rows = read_subclass_signatures(client, signature_set, m.main_id, s.sub_id)
        for r in rows:
            r.main_name, r.sub_name = m.name, s.name
        sigs.extend(rows)
        if progress is not None:
            progress(f"{m.name} > {s.name}", len(sigs))
    return SignatureDB(
        firmware=firmware,
        generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        signature_set=signature_set,
        signatures=sigs)


# --------------------------------------------------------------------------- #
#  Persist the DB to data/signatures.json (path supplied by the Flask view)      #
# --------------------------------------------------------------------------- #
def save_signature_db(db: SignatureDB, path: str | Path) -> str:
    """Write ``db`` to ``path`` as JSON; returns the path written."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({
        "firmware": db.firmware,
        "generated_at": db.generated_at,
        "signature_set": db.signature_set,
        "signatures": [s.__dict__ for s in db.signatures],
    }, ensure_ascii=False), encoding="utf-8")
    return str(p)


def load_signature_db(path: str | Path) -> SignatureDB | None:
    """Load the cached database, or ``None`` if the file is missing / unreadable."""
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    sigs = [Signature(**{k: v for k, v in s.items() if k in Signature.__annotations__})
            for s in raw.get("signatures") or [] if isinstance(s, dict)]
    return SignatureDB(
        firmware=raw.get("firmware") or "",
        generated_at=raw.get("generated_at") or "",
        signature_set=raw.get("signature_set") or "",
        signatures=sigs)
