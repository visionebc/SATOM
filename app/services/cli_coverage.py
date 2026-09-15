"""CLI ↔ API coverage: what the appliance CLI serves that the catalog does not.

The question this answers came from the console: *there are elements on the
FortiWeb that are not in the API and only show up over SSH*. That premise is
half right and the half that is wrong is the useful half —

* the CLI dump is **already captured**. ``services.backup.ssh_config_backup``
  has been running ``show full-configuration`` since 2026-07-04 and storing the
  text in the device vault (``data/backups/<appliance_id>/*.conf``), replicated
  to the standby by ``satom-ha-datasync`` and carried inside the system bundles.
  Nobody read it. Same shape as the sweep ledger that ``api_matrix`` found
  unread on disk;
* so nothing here opens a new network path, a new verb or a new write. This
  module is a **parser and a differ**. Measured against the real artifacts on
  248: FortiWeb 7.6.8 (fortiweb08, 690 KB) → 377 blocks the catalog knows,
  **57 it does not**; FortiADC 8.0.3 (fadc, 176 KB) → 219 known, **81 not**.

The comparison is between two namespaces that were never designed to line up,
so the whole module is shaped around the ways it could quietly lie:

1. **A config table with nothing in it prints NO BLOCK AT ALL.** So "in the
   catalog, absent from this dump" is *not* evidence the firmware lacks it —
   it is evidence nobody configured it. That bucket is named
   :data:`BUCKET_NO_BLOCK` and worded as such everywhere; folding it into
   "absent" would invent ~96 phantom removals on FortiWeb from an empty fleet.
   Same failure ``api_matrix`` RULE 1 exists to prevent.
2. **A dump is evidence about ONE firmware line, measured on ONE device, on
   ONE date** — and every dump in the vault today belongs to an appliance that
   has since been deleted. Every count on the page carries the device and the
   date, and a dump whose product cannot be established from its vault row is
   never diffed at all: guessing would diff a FortiADC dump against the
   FortiWeb catalog and report ~300 fabricated findings.
3. **CLI and REST spell child tables differently.** The FortiWeb catalog has
   ``…/graphql-validation.policy/rule-list`` where the CLI says
   ``graphql-rule-list``. Two real cases in the live dump. Those are NOT
   cli-only (the endpoint exists) and NOT matched (the paths differ) — they are
   :data:`BUCKET_NEAR`, "verify this URN in the console before editing the
   catalog", because either spelling could be the wrong one and this module
   cannot tell which from a config file.
4. **Field deltas are delegated, not recomputed.** ``api_matrix.preflight``
   already knows that comparing sweep field sets against harvested schema
   fields reports 56 removals that are nothing but a noise filter. A CLI
   ``set`` name list is a third kind of evidence; it is handed to that function
   so there is ONE author of the "is this field known on this line?" answer.

Nothing here is persisted. A report is derived on request from files that are
already backed up (parse of the 690 KB FortiWeb dump: ~35 ms measured on 248),
so there is no artifact to go stale, nothing extra in the bundle, and no second
copy of a derived view living in a different backup path from its evidence.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field as _dc_field

from ..registry import loader
from . import api_matrix

# ---------------------------------------------------------------------------
# products
# ---------------------------------------------------------------------------

# Products whose CLI is a ``config … end`` configuration tree that maps onto the
# catalog. The other two are stated, not discovered as an empty page:
#
#   * FortiAnalyzer speaks JSON-RPC (``loader.API_VERSION['fortianalyzer'] ==
#     'jsonrpc'``) and its ``/sys/proxy/json`` reaches objects the CLI does not
#     name at all — the imbalance runs the OTHER way, so a CLI diff would read
#     as "the API has 64 things the CLI lacks" and teach nobody anything;
#   * FortiAuthenticator's CLI is a minimal network shell with no
#     ``show full-configuration`` equivalent; its GUI/API is the superset.
#
# Neither has ever been touched over SSH by this app (``ssh_ops`` is written
# against the FortiWeb prompt and reused, verified, by FortiADC). Shipping a
# parser for them would be shipping three-quarters of a feature that cannot be
# measured against anything.
SUPPORTED_PRODUCTS = ("fortiweb", "fortiadc")

UNSUPPORTED_REASON = {
    "fortianalyzer": (
        "FortiAnalyzer speaks JSON-RPC, not a config CLI: there is no "
        "'show full-configuration' tree to diff, and its /sys/proxy/json "
        "reaches objects the CLI never names — the coverage gap here runs the "
        "opposite way. Measure one FortiAnalyzer over SSH before trusting any "
        "diff this page could show."),
    "fortiauthenticator": (
        "FortiAuthenticator's CLI is a minimal network shell — the GUI/API is "
        "the superset of it, not the subset. No appliance of this kind has "
        "ever been read over SSH by SATOM, so there is no evidence to diff."),
}

# ``config global`` / ``config vdom`` are SCOPE CONTAINERS, not config tables:
# everything real is nested inside them. They are stripped by matching the
# OUTERMOST block exactly — a nested ``config system global`` (a real table,
# ``/api/v2.0/cmdb/system/global``) keeps its ``global`` token, and a top-level
# FortiADC ``config global-dns-server`` is not a container either. Which is why
# the strip happens on the raw words, BEFORE any hyphen splitting.
_SCOPE_CONTAINERS = frozenset({"global", "vdom"})

# Catalog↔CLI token normalisation. Both namespaces separate words with a mix of
# '-', '_', '.' and '/' for reasons that are historical on both sides, so the
# comparable form is the token TUPLE, not any one spelling of the joiner.
_TOKEN_SPLIT = re.compile(r"[-_./]+")

# The FortiADC catalog marks child tables with a literal ``child`` infix
# (``load_balance_pool_child_pool_member``, documented in
# endpoints_fortiadc.yaml). The CLI has no such word. Dropped on the CATALOG
# side only — inventing the convention on the CLI side would match blocks that
# really do have a "child" token.
_ADC_DROP_TOKENS = frozenset({"child"})

BUCKET_BOTH = "both"
BUCKET_CLI_ONLY = "cli_only"
BUCKET_NEAR = "near_match"
BUCKET_NO_BLOCK = "no_block"
BUCKET_MONITOR = "monitor_only"


# ---------------------------------------------------------------------------
# the CLI parser
# ---------------------------------------------------------------------------

@dataclass
class CliBlock:
    """One ``config … end`` block found in a dump."""

    tokens: tuple          # canonical comparable form
    path: str              # the CLI path an operator would type after `show `
    raw_path: str          # including the scope container, as it appears
    depth: int
    line: int              # 1-indexed line of the `config` header
    end_line: int = 0      # 1-indexed line of its `end`
    instances: int = 0     # `edit` rows seen directly inside it
    sets: set = _dc_field(default_factory=set)   # `set`/`unset` field names


def parse_config_dump(text: str) -> dict:
    """``show full-configuration`` text → ``{canonical_tokens: CliBlock}``.

    Structure only; values are never retained (see :func:`scrub_block` for why
    the raw text is handled separately and carefully).

    The one thing that makes this more than a line loop: **a quoted value can
    span lines**, and FortiWeb puts PEM bodies in them
    (``set private-key "-----BEGIN ENCRYPTED PRIVATE KEY-----`` … ). A
    continuation line is arbitrary text, so a line that happens to read ``end``
    inside one would pop a block that never closed and shift every block after
    it into the wrong parent. Quote state is therefore tracked and continuation
    lines are skipped whole.

    A dump whose blocks do not balance is returned as far as it parsed rather
    than raised on: half a coverage report is still useful, and the caller
    reports the imbalance (:func:`parse_report`) instead of showing nothing.
    """
    blocks: dict = {}
    stack: list = []          # list[list[str]] — the words of each open `config`
    open_blocks: list = []    # parallel list[CliBlock|None]
    in_quote = False

    for n, raw in enumerate((text or "").splitlines(), 1):
        if in_quote:
            # Inside a multi-line quoted value: this line is data, not syntax.
            if raw.count('"') % 2:
                in_quote = False
            continue

        line = raw.strip()
        if not line:
            continue

        if line.startswith("config "):
            words = line[7:].split()
            if not words:
                continue
            stack.append(words)
            blk = _register(blocks, stack, n)
            open_blocks.append(blk)
            continue

        if line == "end":
            if stack:
                stack.pop()
                blk = open_blocks.pop()
                if blk is not None and not blk.end_line:
                    blk.end_line = n
            continue

        if line.startswith("edit "):
            blk = open_blocks[-1] if open_blocks else None
            if blk is not None:
                blk.instances += 1
            if line.count('"') % 2:
                in_quote = True
            continue

        if line.startswith("set ") or line.startswith("unset "):
            parts = line.split(None, 2)
            if len(parts) > 1:
                blk = open_blocks[-1] if open_blocks else None
                if blk is not None:
                    blk.sets.add(parts[1])
            if line.count('"') % 2:
                in_quote = True
            continue

    return blocks


def _register(blocks: dict, stack: list, line: int) -> CliBlock | None:
    """Create (or return) the block for the current stack position.

    A path that appears twice — the same table inside two ``config vdom``
    scopes, say — resolves to the SAME canonical key, and the first occurrence
    keeps the record. Counting it twice would make the totals depend on how
    many VDOMs a box has.
    """
    raw_words = [w for seg in stack for w in seg]
    scoped = raw_words
    if len(stack[0]) == 1 and stack[0][0] in _SCOPE_CONTAINERS:
        scoped = [w for seg in stack[1:] for w in seg]
    if not scoped:
        return None
    tokens = _tokens(scoped)
    existing = blocks.get(tokens)
    if existing is not None:
        return existing
    blk = CliBlock(tokens=tokens, path=" ".join(scoped),
                   raw_path=" ".join(raw_words), depth=len(stack), line=line)
    blocks[tokens] = blk
    return blk


def _tokens(words) -> tuple:
    return tuple(t for w in words for t in _TOKEN_SPLIT.split(w) if t)


def parse_report(text: str) -> dict:
    """Structural health of a dump — read BEFORE its numbers are believed.

    ``show full-configuration`` output that was truncated by a read timeout
    looks exactly like a small config, and ``ssh_config_backup`` only refuses
    the ones that fail its header/footer check. A dump whose blocks do not
    balance produces a real, plausible, WRONG coverage report, so the caller
    shows this beside the counts.
    """
    body = (text or "").strip()
    depth = 0
    in_quote = False
    min_depth = 0
    for raw in body.splitlines():
        if in_quote:
            if raw.count('"') % 2:
                in_quote = False
            continue
        line = raw.strip()
        if line.startswith("config "):
            depth += 1
        elif line == "end":
            depth -= 1
            min_depth = min(min_depth, depth)
        elif (line.startswith("set ") or line.startswith("edit ")) and line.count('"') % 2:
            in_quote = True
    return {
        "bytes": len(body),
        "balanced": depth == 0 and min_depth == 0,
        "unclosed": depth,
        "starts_with_config": body.startswith("config"),
        "ends_with_end": body.endswith("end"),
        "open_quote": in_quote,
    }


# ---------------------------------------------------------------------------
# secrets — the dump is a device configuration, and it carries credentials
# ---------------------------------------------------------------------------

# Measured in the live vault copy of fortiweb08: ``set private-key "-----BEGIN
# ENCRYPTED PRIVATE KEY-----`` (PEM bodies over many lines), ``set secret ENC
# …``, ``set password ENC …``. FortiWeb stores these obfuscated, not hashed —
# ``ENC`` is reversible with the device key — so they are secrets, and the vault
# is gated on ``Permission.BACKUP`` for exactly that reason. This page shows
# BLOCK TEXT, so it scrubs before rendering and its raw-text route carries the
# same permission.
_ENC_VALUE = re.compile(r"^(?P<head>\s*(?:set|unset)\s+\S+\s+)ENC\s+\S+.*$")
_PEM_START = re.compile(r"-----BEGIN [A-Z0-9 ]+-----")

# Name-shaped fallback for a plaintext secret that is not ``ENC``-prefixed.
# Deliberately paired with a value test: ``set forbid-password-reuse disable``,
# ``set force-password-change disable`` and ``set key-max-length 1024`` all
# match the name pattern and none of them is a secret. Redacting them would
# hide real configuration in the name of hiding nothing.
_SECRET_NAME = re.compile(
    r"(pass|passwd|secret|psk|private-key|privkey|keytab|token|credential)", re.I)
_HARMLESS_VALUE = re.compile(r"^(?:enable|disable|\d+|)$", re.I)

REDACTED = "<redacted by SATOM>"


def scrub_block(text: str) -> str:
    """Redact credential VALUES from CLI text, keeping every field NAME.

    The names are the whole point of this page (they are what the catalog is
    missing); the values are what must not reach a browser. So a redaction
    always leaves the ``set <name>`` intact.

    The unit of work is the **quoted value, not the line** — and that is not a
    detail. A first version of this walked PEM markers instead, and against the
    real ``system admin-certificate local`` block of fortiweb08 it produced two
    visible defects: a certificate CHAIN holds several ``-----BEGIN`` blocks
    inside ONE value, so every block after the first was emitted as its own
    half-line of leaked structure; and the closing ``"`` sits on its own line
    after ``-----END``, so it survived as a stray quote. Both are cosmetic, but
    a scrubber whose output looks corrupted is a scrubber nobody believes is
    complete. Tracking the quote handles certificates, keys, multi-line scripts
    and anything added later with one rule.

    A multi-line value is only redacted when the field NAME is credential
    shaped or the body carries a PEM header; otherwise it is kept verbatim —
    consumed as a unit either way, so the surrounding structure can never be
    broken by whatever is inside it.
    """
    lines = (text or "").splitlines()
    out: list = []
    i = 0
    while i < len(lines):
        raw = lines[i]
        stripped = raw.strip()
        parts = stripped.split(None, 2)
        is_setter = len(parts) >= 2 and parts[0] in ("set", "unset")
        indent = raw[:len(raw) - len(raw.lstrip())]

        # --- a value that spans lines: consume the whole thing ---------------
        if is_setter and stripped.count('"') % 2:
            body = [raw]
            i += 1
            while i < len(lines):
                body.append(lines[i])
                if lines[i].count('"') % 2:
                    i += 1
                    break
                i += 1
            joined = "\n".join(body)
            if _SECRET_NAME.search(parts[1]) or _PEM_START.search(joined):
                out.append(f'{indent}{parts[0]} {parts[1]} "{REDACTED}"')
            else:
                out.extend(body)
            continue

        i += 1
        m = _ENC_VALUE.match(raw)
        if m:
            out.append(f"{m.group('head')}ENC {REDACTED}")
            continue
        if (len(parts) >= 3 and is_setter
                and _SECRET_NAME.search(parts[1])
                and not _HARMLESS_VALUE.match(parts[2].strip().strip('"'))):
            out.append(f"{indent}{parts[0]} {parts[1]} {REDACTED}")
            continue
        out.append(raw)
    return "\n".join(out)


def extract_block(text: str, path: str, *, scrub: bool = True) -> str:
    """The raw lines of the block at CLI ``path`` — phase B's operational read.

    ``path`` is the canonical (container-stripped) path, so the same string the
    coverage table shows is the string that comes back, and it is also exactly
    what an operator would type after ``show ``.
    """
    want = _tokens(path.split())
    blocks = parse_config_dump(text)
    blk = blocks.get(want)
    if blk is None:
        return ""
    lines = (text or "").splitlines()
    end = blk.end_line or len(lines)
    body = "\n".join(lines[blk.line - 1:end])
    return scrub_block(body) if scrub else body


# ---------------------------------------------------------------------------
# the catalog side
# ---------------------------------------------------------------------------

def _catalog(product: str) -> tuple[dict, list, dict]:
    """``({tokens: [entry…]}, [monitor_entry…], {tokens: [entry…]} aliases)``.

    FortiWeb: only ``/cmdb/`` endpoints can have a CLI block at all. The other
    42 (``/wvs/…``, ``system/status.systemstatus``, the monitor families) are
    runtime readouts with no configuration table behind them, so they are
    separated out rather than counted as gaps — a page whose headline number
    includes 42 entries that CANNOT match is a page nobody trusts twice.
    """
    if product == "fortiweb":
        reg = loader.load_registry()
    elif product == "fortiadc":
        reg = loader.load_adc_registry()
    else:
        return {}, [], {}

    keyed: dict = {}
    monitor: list = []
    for name in sorted(reg):
        urn = reg[name]
        entry = {"name": name, "urn": urn}
        tokens = _catalog_tokens(product, urn)
        if tokens is None:
            monitor.append(entry)
            continue
        keyed.setdefault(tokens, []).append(entry)

    # Two catalog names on one canonical key is not an error — it is how the
    # same table gets a second friendly alias — but it must be visible, because
    # every count below would otherwise silently pick one of them.
    aliases = {k: v for k, v in keyed.items() if len(v) > 1}
    return keyed, monitor, aliases


def _catalog_tokens(product: str, urn: str) -> tuple | None:
    """Canonical tokens for a catalog URN, or ``None`` when it cannot have a
    CLI block by construction (a monitor/runtime endpoint)."""
    u = (urn or "").strip().strip("/").split("?")[0]
    if product == "fortiweb":
        if "/cmdb/" not in "/" + u:
            return None
        tail = u.split("/cmdb/", 1)[1] if "/cmdb/" in u else u
        return _tokens([tail]) or None
    if product == "fortiadc":
        if not u.startswith("api/"):
            return None
        toks = tuple(t for t in _tokens([u[4:]]) if t not in _ADC_DROP_TOKENS)
        return toks or None
    return None


# ---------------------------------------------------------------------------
# the comparison
# ---------------------------------------------------------------------------

def compare(product: str, text: str, *, line: str = "") -> dict:
    """Diff one CLI dump against the product catalog.

    ``line`` is the firmware line (``"7.6"``) the dump was captured on; it is
    only used to ask ``api_matrix`` about fields, and an empty value makes that
    answer ``unmeasured`` rather than wrong.
    """
    if product not in SUPPORTED_PRODUCTS:
        return {"product": product, "supported": False,
                "reason": UNSUPPORTED_REASON.get(
                    product, "no CLI evidence path exists for this product"),
                "counts": {}, BUCKET_CLI_ONLY: [], BUCKET_NEAR: [],
                BUCKET_BOTH: [], BUCKET_NO_BLOCK: [], BUCKET_MONITOR: [],
                "aliases": [], "health": {}}

    health = parse_report(text)
    blocks = parse_config_dump(text)
    keyed, monitor, aliases = _catalog(product)

    # Near-match index: same token SET, different token ORDER or a different
    # child-table name. Keyed by frozenset so it cannot collide with the exact
    # index it complements.
    by_set: dict = {}
    for tokens in keyed:
        by_set.setdefault(frozenset(tokens), []).append(tokens)

    both, cli_only, near = [], [], []
    for tokens, blk in blocks.items():
        entries = keyed.get(tokens)
        if entries:
            both.append({
                "path": blk.path, "tokens": list(tokens),
                "catalog": entries[0]["name"], "urn": entries[0]["urn"],
                "aliases": [e["name"] for e in entries[1:]],
                "instances": blk.instances, "settings": sorted(blk.sets),
                "depth": blk.depth, "line": blk.line,
            })
            continue
        hit = by_set.get(frozenset(tokens))
        rec = {
            "path": blk.path, "tokens": list(tokens),
            "instances": blk.instances, "settings": sorted(blk.sets),
            "depth": blk.depth, "line": blk.line,
            "configured": bool(blk.instances or blk.sets),
        }
        if hit:
            cand = keyed[hit[0]][0]
            rec["catalog"] = cand["name"]
            rec["urn"] = cand["urn"]
            near.append(rec)
        else:
            cli_only.append(rec)

    seen = set(blocks)
    no_block = [
        {"catalog": entries[0]["name"], "urn": entries[0]["urn"],
         "tokens": list(tokens)}
        for tokens, entries in sorted(keyed.items())
        if tokens not in seen
        and frozenset(tokens) not in {frozenset(b["tokens"]) for b in near}
    ]

    both.sort(key=lambda r: r["path"])
    cli_only.sort(key=lambda r: r["path"])
    near.sort(key=lambda r: r["path"])

    return {
        "product": product, "supported": True, "reason": "", "line": line,
        "health": health,
        "counts": {
            "cli_blocks": len(blocks),
            "catalog_config": len(keyed),
            "catalog_monitor": len(monitor),
            BUCKET_BOTH: len(both),
            BUCKET_CLI_ONLY: len(cli_only),
            BUCKET_NEAR: len(near),
            BUCKET_NO_BLOCK: len(no_block),
            # Of the CLI-only findings, the ones that actually hold
            # configuration on this box. A table the operator has never filled
            # in is a smaller catalog gap than one carrying 69 rows.
            "cli_only_configured": sum(1 for r in cli_only if r["configured"]),
        },
        BUCKET_BOTH: both,
        BUCKET_CLI_ONLY: cli_only,
        BUCKET_NEAR: near,
        BUCKET_NO_BLOCK: no_block,
        BUCKET_MONITOR: monitor,
        "aliases": [{"tokens": list(k), "names": [e["name"] for e in v]}
                    for k, v in sorted(aliases.items())],
    }


def field_gap(product: str, line: str, catalog_name: str, settings) -> dict:
    """Which CLI ``set`` names our recorded API field evidence does not know.

    Delegated ENTIRELY to :func:`api_matrix.preflight`. That function already
    carries the rule this would otherwise get wrong on its own — that a sweep
    field set and a harvested schema field set are different kinds of evidence
    and comparing across them reports dozens of removals that are only a noise
    filter — and it already distinguishes ``unmeasured`` from ``ok``. A second
    implementation here would be a second author of the same answer.
    """
    if not line:
        return {"status": api_matrix.STATUS_UNMEASURED, "unknown": [], "known": [],
                "reason": "the dump does not record which firmware line it was "
                          "captured on, so no field evidence can be selected"}
    return api_matrix.preflight(product, line, catalog_name, settings)


# ---------------------------------------------------------------------------
# evidence — the dumps already in the vault
# ---------------------------------------------------------------------------

_PRODUCT_MARKERS = (
    ("fortiweb", "fortiweb"),
    ("fortiadc", "fortiadc"),
    ("fortianalyzer", "fortianalyzer"),
    ("fortiauthenticator", "fortiauthenticator"),
)


def product_of_firmware(firmware: str | None) -> str:
    """``"FortiWeb-KVM 7.6.8,build1128"`` → ``"fortiweb"``; ``""`` if unknown.

    The vault row's ``firmware`` string was recorded BY THE CAPTURE, from the
    device, which makes it better evidence than either the filename or the
    appliance row: every dump in the vault today belongs to an appliance that
    has since been deleted (``fw1``, ``fw6``, ``fw7``, ``fadc``, ``fortiweb08``
    — verified on 248), so the row is the only surviving statement of what kind
    of box it came from.
    """
    f = (firmware or "").lower()
    for key, marker in _PRODUCT_MARKERS:
        if marker in f:
            return key
    return ""


def evidence_index(product: str | None = None) -> list:
    """Vault dumps usable as CLI evidence, newest first.

    A row is usable only when its product can be ESTABLISHED (never guessed),
    it is not device-encrypted, and the file is on disk and opens as
    ``config``… Everything else is listed with the reason it cannot be used, on
    purpose: a dump silently missing from this list is indistinguishable from a
    device that was never captured.
    """
    from ..models_backup import ConfigBackup

    out: list = []
    for row in ConfigBackup.query.order_by(ConfigBackup.created_at.desc()).all():
        prod = product_of_firmware(row.firmware)
        rec = {
            "backup_id": row.id, "appliance_id": row.appliance_id,
            "appliance": row.appliance_name or "?",
            "filename": row.filename,
            "created_at": row.created_at.strftime("%Y-%m-%d %H:%M")
                          if row.created_at else "",
            # The machine-readable twin of ``created_at``. The display string
            # is formatted for a table cell; anything deriving a BUDGET from it
            # (see rediscovery.CLI_CAPTURE_MAX_AGE_H) would be one column
            # change away from silently never firing again.
            "created_iso": row.created_at.isoformat() if row.created_at else "",
            "firmware": row.firmware or "",
            "product": prod,
            "line": api_matrix.firmware_line(row.firmware),
            # The FULL version, beside the line. A dump is captured from ONE
            # box running ONE build, and labelling it only ``8.0`` throws away
            # the only thing that could ever distinguish 8.0.3's CLI from
            # 8.0.7's — which is exactly the difference the operator asked
            # this page to make visible.
            "version": api_matrix.firmware_version(row.firmware),
            "size_kb": (row.size_bytes or 0) // 1024,
            "source": row.source,
            "usable": False, "reason": "",
        }
        if row.encrypted:
            rec["reason"] = ("the device encrypted this backup (a backup "
                            "password is set) — its text cannot be parsed")
        elif not prod:
            rec["reason"] = ("the vault row does not record which product this "
                            "came from, and guessing would diff it against the "
                            "wrong catalog")
        elif prod not in SUPPORTED_PRODUCTS:
            rec["reason"] = UNSUPPORTED_REASON.get(prod, "unsupported product")
        elif not os.path.isfile(row.stored_path or ""):
            rec["reason"] = "the stored file is missing from disk"
        else:
            rec["usable"] = True
        out.append(rec)
    if product:
        out = [r for r in out if r["product"] == product]
    return out


def read_dump(backup_id: int) -> tuple[str, dict]:
    """``(text, evidence_record)`` for one vault row, or ``("", {})``.

    Refuses anything :func:`evidence_index` called unusable — the refusal is
    the point: a caller that could bypass it would be diffing a FortiADC
    config against the FortiWeb catalog on the strength of a URL parameter.
    """
    from ..models_backup import ConfigBackup

    row = ConfigBackup.query.get(backup_id)
    if row is None:
        return "", {}
    rec = next((r for r in evidence_index() if r["backup_id"] == backup_id), None)
    if not rec or not rec["usable"]:
        return "", (rec or {})
    try:
        with open(row.stored_path, "rb") as fh:
            text = fh.read().decode("utf-8", "replace")
    except OSError as exc:
        rec = dict(rec, usable=False, reason="the stored file could not be read (%s)" % exc)
        return "", rec
    if not text.lstrip().startswith("config"):
        rec = dict(rec, usable=False,
                   reason="the stored file does not start with 'config' — it is "
                          "not a CLI configuration dump")
        return "", rec
    return text, rec


def orphan_dumps() -> list:
    """Dump files on disk with no vault row — listed, never parsed.

    Four exist on 248 (``fw1`` × 2, and two more whose rows were deleted). With
    no row there is no recorded firmware, so there is no way to know which
    catalog to compare them against. They are surfaced because a file holding a
    device configuration that nothing in the app knows about is worth seeing.
    """
    from ..models_backup import ConfigBackup
    from .backup import vault_root  # single source of the vault path

    known = {os.path.abspath(r.stored_path or "")
             for r in ConfigBackup.query.all()}
    root = vault_root()
    out: list = []
    if not os.path.isdir(root):
        return out
    for sub in sorted(os.listdir(root)):
        d = os.path.join(root, sub)
        if not os.path.isdir(d):
            continue
        for fname in sorted(os.listdir(d)):
            full = os.path.abspath(os.path.join(d, fname))
            if full in known:
                continue
            try:
                size = os.path.getsize(full)
            except OSError:
                continue
            out.append({"path": os.path.join(sub, fname), "size_kb": size // 1024})
    return out


def report(product: str, backup_id: int | None = None, *,
           line: str = "", version: str = "") -> dict:
    """The whole page payload for one product: evidence list + the diff.

    With no ``backup_id`` the newest usable dump for the product is used, so
    the section is never blank when there IS evidence — and when there is none
    it says which appliance to capture, not "0".

    ``line`` restricts the choice to dumps captured on one firmware line, for
    the firmware-line comparison page. It is a FILTER, never a fallback: with
    no dump on that line the answer is *no evidence for 8.0*, not the 7.6 dump
    relabelled. Answering a question about one firmware with a capture from
    another is the single way this page could mislead, and it would look
    exactly like a confident answer.
    """
    evidence = evidence_index(product) if product in SUPPORTED_PRODUCTS else []
    usable = [e for e in evidence if e["usable"]]
    # ``version`` is the stricter filter and wins when both are given. Same
    # never-a-fallback rule as ``line``: no dump on 8.0.5 means *no evidence
    # for 8.0.5*, not the 8.0.3 dump relabelled. Answering a question about one
    # build with a capture from another looks exactly like a confident answer.
    if version:
        usable = [e for e in usable if e.get("version") == version]
    elif line:
        usable = [e for e in usable if e.get("line") == line]
    chosen = None
    if backup_id:
        chosen = next((e for e in usable if e["backup_id"] == backup_id), None)
    if chosen is None:
        chosen = usable[0] if usable else None

    if chosen is None:
        diff = compare(product, "") if product in SUPPORTED_PRODUCTS else compare(product, "")
        diff["no_evidence"] = True
        diff["evidence_line"] = version or line
        return {"product": product, "evidence": evidence, "chosen": None,
                "line_filter": line, "version_filter": version,
                "diff": diff, "orphans": orphan_dumps()}

    text, rec = read_dump(chosen["backup_id"])
    diff = compare(product, text, line=chosen.get("line", ""))
    diff["no_evidence"] = not text
    diff["evidence_line"] = version or line
    return {"product": product, "evidence": evidence, "chosen": rec or chosen,
            "line_filter": line, "version_filter": version,
            "diff": diff, "orphans": orphan_dumps()}


# ---------------------------------------------------------------------------
# promoting a finding into the catalog
# ---------------------------------------------------------------------------

# A CLI block with four segments below the family yields 8 joiner combinations.
# Capped so a single row cannot fire an unbounded number of GETs at an appliance,
# and the cap is reported rather than silently applied.
MAX_CANDIDATES = 8


def catalog_name_for(path: str) -> str:
    """CLI path → the friendly key the catalog would use for it.

    Underscore-joined canonical tokens, which is what the catalog already looks
    like (``system_admin``, ``log_custom_sensitive_rule``) — so a promoted entry
    is indistinguishable from a seeded one instead of announcing which tool made
    it.
    """
    return "_".join(_tokens(path.split()))


def candidate_urns(product: str, path: str) -> list:
    """Plausible REST paths for one CLI block. A LIST, on purpose.

    FortiWeb joins the segments below the family with ``.`` for a SUB-TABLE
    (``system/certificate.local``, ``server-policy/service.predefined``) and with
    ``/`` for a CHILD LIST (``server-policy/policy/http-content-routing-list``)
    — and the CLI spells both exactly the same way. A single derived path would
    be a coin flip presented as a fact, and it would be written into the catalog,
    where every service resolves names through ``loader.resolve``. So every
    combination is offered and the **device** decides which one exists; that same
    ambiguity is why the ``near_match`` bucket has to exist at all.

    FortiADC is nearly deterministic (``config a-b c`` → ``/api/a_b_c``) with one
    documented variant: the ``_child_`` infix its catalog uses for child tables,
    which the CLI does not have.
    """
    words = (path or "").split()
    if len(words) < 2:
        return []
    if product == "fortiweb":
        family, rest = words[0], words[1:]
        if len(rest) == 1:
            return ["/api/v2.0/cmdb/%s/%s" % (family, rest[0])]
        out = []
        for mask in range(2 ** (len(rest) - 1)):
            joined = rest[0]
            for i, w in enumerate(rest[1:]):
                joined += ("/" if (mask >> i) & 1 else ".") + w
            out.append("/api/v2.0/cmdb/%s/%s" % (family, joined))
        return out[:MAX_CANDIDATES]
    if product == "fortiadc":
        flat = [w.replace("-", "_") for w in words]
        out = ["/api/" + "_".join(flat)]
        if len(flat) >= 3:
            out.append("/api/" + "_".join(flat[:-1]) + "_child_" + flat[-1])
        return out[:MAX_CANDIDATES]
    return []


# ---------------------------------------------------------------------------
# provenance — which transport serves one catalog entry
# ---------------------------------------------------------------------------
# Three pages list catalog entries — the API hub's menu tree, the firmware-line
# comparison and the object Structure cross-reference — and all three were asked
# the same question: *is this served by the API, by the CLI, or by both?*
#
# ONE derivation, from the diff those pages already compute. A second one would
# be the ``api.js`` / ``main.js`` status-badge split repeated: two authors of one
# badge, drifting apart at the first edit. Everything below is a projection of
# :func:`compare` — it never re-parses a dump and never re-reads the catalog.

PROV_UNKNOWN = "unknown"

#: Every value :meth:`Provenance.for_name` / :meth:`Provenance.for_urn` can
#: return. Finding-first, so a page that groups by bucket leads with the gap.
PROV_ORDER = (BUCKET_CLI_ONLY, BUCKET_NEAR, BUCKET_BOTH, BUCKET_NO_BLOCK,
              BUCKET_MONITOR, PROV_UNKNOWN)

#: ``bucket -> (label, css class, why)``. The vocabulary lives here rather than
#: in three templates so the three pages cannot disagree about what a word
#: means. ``PROV_UNKNOWN`` deliberately has NO badge class: a page renders it as
#: an em dash, because a grey badge saying "unknown" sits in the same visual
#: family as a grey badge saying "no CLI block", and those two are precisely the
#: pair that must never be confused.
PROV_LABEL = {
    BUCKET_BOTH: ("API + CLI", "fw-badge-success",
                  "the catalog serves it over REST and the CLI dump has its "
                  "configuration block"),
    BUCKET_NEAR: ("API + CLI · other path", "fw-badge-warning",
                  "both transports carry it, but the CLI spells the path "
                  "differently from the REST URN — neither a match nor a gap"),
    BUCKET_MONITOR: ("API only", "fw-badge-info",
                     "a runtime readout with no configuration table behind it, "
                     "so it cannot have a CLI block by construction"),
    BUCKET_NO_BLOCK: ("API · no CLI block here", "fw-badge-secondary",
                      "the catalog serves it, and this dump has no block for "
                      "it — an EMPTY table prints no block, so this is not "
                      "evidence that the CLI lacks it"),
    BUCKET_CLI_ONLY: ("CLI only", "fw-badge-danger",
                      "the dump has a configuration block for it and the "
                      "catalog has no endpoint that matches"),
    PROV_UNKNOWN: ("—", "", "no CLI evidence has been measured for this"),
}


class Provenance:
    """Transport provenance for a product's catalog, against ONE CLI dump.

    Built by :func:`provenance`; consumed by the API hub, the firmware-line
    comparison and the Structure cross-reference through :meth:`for_name` and
    :meth:`for_urn`.

    The rule that makes it trustworthy is :attr:`measured`. With no usable dump
    :func:`compare` still returns a full result — and in it **every** catalog
    entry lands in ``no_block``, because an absent dump has no blocks. Rendered
    naively that reads *"the CLI has none of this"*, which is the exact opposite
    of what an empty evidence set means. So when nothing was measured the only
    answers this object will give are ``monitor_only`` — which follows from the
    URN alone and holds with or without a dump — and ``unknown``.
    """

    __slots__ = ("product", "supported", "reason", "evidence", "counts",
                 "by_name", "by_tokens", "cli_only")

    def __init__(self, product, *, supported, reason, evidence, counts,
                 by_name, by_tokens, cli_only):
        self.product = product
        self.supported = supported
        self.reason = reason
        self.evidence = evidence
        self.counts = counts
        self.by_name = by_name
        self.by_tokens = by_tokens
        self.cli_only = cli_only

    # -- state ------------------------------------------------------------
    @property
    def measured(self) -> bool:
        """True only when a usable dump backed this object."""
        return bool(self.supported) and self.evidence is not None

    @property
    def device(self) -> str:
        return (self.evidence or {}).get("appliance", "")

    @property
    def captured_at(self) -> str:
        return (self.evidence or {}).get("created_at", "")

    @property
    def line(self) -> str:
        return (self.evidence or {}).get("line", "")

    # -- lookups ----------------------------------------------------------
    def _unknown(self, why: str = "") -> dict:
        return {"bucket": PROV_UNKNOWN, "why": why or self.reason,
                "path": "", "catalog": "", "urn": "", "configured": False}

    def for_name(self, name: str) -> dict:
        """Provenance of a catalog entry addressed by its friendly name."""
        if not name:
            return self._unknown("no catalog name")
        rec = self.by_name.get(name)
        if rec is not None:
            return rec
        if not self.measured:
            return self._unknown()
        return self._unknown(
            "%r is not an entry in the %s catalog, so there is nothing to "
            "compare a CLI block against" % (name, self.product))

    def for_urn(self, urn: str) -> dict:
        """Provenance of a REST URN, for rows that carry a URN and no name.

        A URN that cannot host a CLI block at all (a monitor/runtime path) is
        answered from the URN alone — that fact does not depend on holding a
        dump, so withholding it would be false modesty rather than honesty.
        """
        if not urn:
            return self._unknown("no URN")
        tokens = _catalog_tokens(self.product, urn)
        if tokens is None:
            return {"bucket": BUCKET_MONITOR, "why": PROV_LABEL[BUCKET_MONITOR][2],
                    "path": "", "catalog": "", "urn": urn, "configured": False}
        rec = self.by_tokens.get(tokens)
        if rec is not None:
            return rec
        if not self.measured:
            return self._unknown()
        return {"bucket": BUCKET_NO_BLOCK, "why": PROV_LABEL[BUCKET_NO_BLOCK][2],
                "path": "", "catalog": "", "urn": urn, "configured": False}


def provenance_from(diff: dict, evidence: dict | None) -> Provenance:
    """Project one :func:`compare` result into a :class:`Provenance`.

    Pure and cheap on purpose: the API hub already holds a ``compare`` result
    when it renders, so its badges cost no second parse of a 690 KB dump.
    """
    product = diff.get("product", "")
    supported = bool(diff.get("supported"))
    # ``no_evidence`` is set by ``report`` when nothing could be read. It is the
    # hinge of this whole module — see Provenance.measured.
    if diff.get("no_evidence"):
        evidence = None
    reason = diff.get("reason") or ""
    if supported and evidence is None:
        line = diff.get("evidence_line") or ""
        reason = ("no usable CLI dump has been captured for %s%s, so nothing "
                  "here can be called API-only" %
                  (product, " on firmware line %s" % line if line else ""))

    by_name: dict = {}
    by_tokens: dict = {}

    def _put(rec, names):
        for nm in names:
            if nm:
                by_name.setdefault(nm, rec)
        toks = rec.get("tokens")
        if toks:
            by_tokens.setdefault(tuple(toks), rec)

    # monitor_only survives an absent dump: it is derived from the URN shape,
    # not from evidence.
    for ent in diff.get(BUCKET_MONITOR) or []:
        by_name.setdefault(ent["name"], {
            "bucket": BUCKET_MONITOR, "why": PROV_LABEL[BUCKET_MONITOR][2],
            "path": "", "catalog": ent["name"], "urn": ent.get("urn", ""),
            "configured": False})

    if evidence is not None:
        for bucket in (BUCKET_BOTH, BUCKET_NEAR):
            for r in diff.get(bucket) or []:
                rec = {"bucket": bucket, "why": PROV_LABEL[bucket][2],
                       "path": r.get("path", ""), "catalog": r.get("catalog", ""),
                       "urn": r.get("urn", ""), "tokens": r.get("tokens") or [],
                       "instances": r.get("instances", 0),
                       "settings": r.get("settings") or [],
                       "configured": bool(r.get("instances") or r.get("settings"))}
                _put(rec, [r.get("catalog")] + list(r.get("aliases") or []))
        for r in diff.get(BUCKET_CLI_ONLY) or []:
            rec = {"bucket": BUCKET_CLI_ONLY, "why": PROV_LABEL[BUCKET_CLI_ONLY][2],
                   "path": r.get("path", ""), "catalog": "", "urn": "",
                   "tokens": r.get("tokens") or [],
                   "instances": r.get("instances", 0),
                   "settings": r.get("settings") or [],
                   "configured": bool(r.get("configured"))}
            _put(rec, [])
        for r in diff.get(BUCKET_NO_BLOCK) or []:
            rec = {"bucket": BUCKET_NO_BLOCK, "why": PROV_LABEL[BUCKET_NO_BLOCK][2],
                   "path": "", "catalog": r.get("catalog", ""),
                   "urn": r.get("urn", ""), "tokens": r.get("tokens") or [],
                   "configured": False}
            _put(rec, [r.get("catalog")])

    # Completeness. ``compare`` drops a catalog entry from ``no_block`` when ANY
    # near-match shares its token SET, but only the FIRST entry of that set is
    # named as the near candidate — so an entry could end up in no bucket, and
    # ``for_name`` would then answer "that is not in the catalog" about
    # something that is. The sweep is over the same ``_catalog`` the diff was
    # built from, so it cannot introduce a name the diff never considered.
    if evidence is not None:
        near_sets = {frozenset(r.get("tokens") or [])
                     for r in diff.get(BUCKET_NEAR) or []}
        keyed, _monitor, _aliases = _catalog(product)
        for tokens, entries in keyed.items():
            bucket = (BUCKET_NEAR if frozenset(tokens) in near_sets
                      else BUCKET_NO_BLOCK)
            for ent in entries:
                if ent["name"] in by_name:
                    continue
                by_name[ent["name"]] = {
                    "bucket": bucket, "why": PROV_LABEL[bucket][2], "path": "",
                    "catalog": ent["name"], "urn": ent.get("urn", ""),
                    "tokens": list(tokens), "configured": False}

    return Provenance(
        product, supported=supported, reason=reason, evidence=evidence,
        counts=diff.get("counts") or {}, by_name=by_name, by_tokens=by_tokens,
        cli_only=list(diff.get(BUCKET_CLI_ONLY) or []) if evidence is not None else [],
    )


def provenance(product: str, backup_id: int | None = None, *,
               line: str = "", version: str = "") -> Provenance:
    """Transport provenance for ``product``, from the best evidence available.

    ``line`` selects evidence captured on one firmware line and ``version``
    on one exact build — see :func:`report`, which owns evidence selection for
    every caller. ``version`` is the stricter of the two and wins.
    """
    rep = report(product, backup_id, line=line, version=version)
    return provenance_from(rep["diff"], rep.get("chosen"))


__all__ = [
    "SUPPORTED_PRODUCTS", "UNSUPPORTED_REASON", "REDACTED", "MAX_CANDIDATES",
    "catalog_name_for", "candidate_urns",
    "BUCKET_BOTH", "BUCKET_CLI_ONLY", "BUCKET_NEAR", "BUCKET_NO_BLOCK",
    "BUCKET_MONITOR",
    "CliBlock", "parse_config_dump", "parse_report", "scrub_block",
    "extract_block", "compare", "field_gap", "product_of_firmware",
    "evidence_index", "read_dump", "orphan_dumps", "report",
    "PROV_UNKNOWN", "PROV_ORDER", "PROV_LABEL", "Provenance",
    "provenance", "provenance_from",
]
