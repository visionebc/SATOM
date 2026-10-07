"""API library packs — move what one SATOM knows about vendor APIs to another.

Design contract: ``docs/api-library.md`` §11. Why this exists: an installation
with no internet and no appliance of a given build has no way to learn what
that build serves. Sweeps need the box, the vendor collections need Galaxy,
and the release notes and field catalog need docs.fortinet.com. A pack carries
all three kinds of knowledge as one signed tarball, so an offline node imports
it the same way it applies an update package. Packs are written by SATOM's own
export below and by the separate harvester tool, in the same schema; this
module imports both unchanged.

Layout (a gzip tarball with exactly one top-level directory)::

    satom-apipack-<version>/
        manifest.json       the signed document: items + sha256 of every file
        manifest.sig        Ed25519 over manifest.json's exact bytes
        library/<product>/<source>-<scope>-<sha12>.json.gz   one evidence doc
        docs/release-notes/<product>.json.gz                 corpus, full text
        docs/field-schemas/<product>/<line>.json.gz          {object: schema}
        docs/fortiweb-field-overlay.json.gz
        cli-coverage/<product>/<version>.json.gz             CLI-only names

The rules, each one a way a pack could do harm:

1. **A pack never carries a configuration.** Sweep evidence is stored with
   the raw snapshot, and that snapshot holds the rows the box returned — real
   configuration. Export re-derives the normalised document from the raw blob
   (field NAMES and types only), and refuses any row whose re-derived hash is
   not the stored hash: a document that does not reproduce the measurement is
   not exported as if it did. CLI dumps never leave either; only block paths,
   ``set`` names and counts.
2. **A pack never names our estate.** Device names are replaced by a stable
   pseudonym (HMAC with a per-installation salt, so the next pack's witness is
   the same witness and re-import deduplicates), serials and appliance ids are
   dropped, and :func:`_leak_scan` refuses the WHOLE export if any known
   device name, serial or appliance address survives anywhere in a payload.
3. **Local measurement wins.** A pack sweep or schema for a build this node
   has measured itself is skipped, release notes for a (product, version) the
   node already holds are skipped, and a field schema file that exists locally
   is never overwritten. Import only ever adds. One exception: LAB evidence
   of a knowledge pack (``summary.lab`` — fresh rows a lab box created to
   reveal tables a production box has empty) is imported next to the
   node's own: it can only fill what the node could not measure.
4. **Signed or refused, by the right key.** An unsigned pack and a badly
   signed one are the same refusal. Which keys count depends on the schema
   (docs/api-library.md §12, SATOM 3.0):

   * ``satom.api-pack/2`` carries a ``lane`` (``api_pack`` | ``knowledge``)
     and is verified ONLY with that lane's keys: ``deploy/pack-keys/<lane>/``
     (shipped in the release-signed code tree) plus
     ``/etc/satom/pack-keys/<lane>/`` (operator-added, root-owned). The
     release key never signs a /2 pack, a knowledge key never signs an
     api_pack, and the ``harvester`` transport lane is never imported.
   * ``satom.api-pack/1`` (2.13 and older, no lane) is verified ONLY with the
     update trust store, as before, so the packs already in ``api-packs/``
     still import.

   The update verifier never reads a pack key (``update_package.verify_signature``).

3.0 adds item kinds beyond the three sections above (factory catalog, rename
candidates, baselines, signature metadata), a provenance on every imported row
(``local`` | ``pack:api_pack:<pack>`` | ``pack:knowledge:<pack>``) and REPLACE
semantics for pack-owned copies: local data > api_pack > knowledge, and inside
a lane the newer pack wins. Kind payloads are validated; a malformed item is
rejected with a message and never stops the rest of the import.
"""
from __future__ import annotations

import gzip
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import tarfile
import tempfile
from datetime import datetime
from pathlib import Path

from flask import current_app

from ..extensions import db
from ..models_apilib import ApiLibBuild, ApiLibEvidence
from . import api_library as lib
from . import firmware_versions as fv
from .update_package_service import TRUST_DIR, up

SCHEMA_V1 = "satom.api-pack/1"
SCHEMA_V2 = "satom.api-pack/2"
#: What :func:`export_pack` writes. Legacy: the release pipeline builds /2
#: packs from satom-harvester snapshots and no longer calls the export.
SCHEMA = SCHEMA_V1
SCHEMAS = (SCHEMA_V1, SCHEMA_V2)
PRODUCT = "satom"

LANE_API_PACK = "api_pack"
LANE_KNOWLEDGE = "knowledge"
LANES = (LANE_API_PACK, LANE_KNOWLEDGE)
#: harvester -> publisher transport; signed with a key no node trusts.
LANE_TRANSPORT = "harvester"
#: C6 precedence between pack lanes (local data outranks both).
LANE_RANK = {LANE_KNOWLEDGE: 1, LANE_API_PACK: 2}
#: Manifest keys every /2 pack must carry.
V2_REQUIRED = ("lane", "min_satom", "publisher", "content_fingerprint", "snapshot",
               "pinned_to", "sections")

PROV_LOCAL = "local"
PROV_PREFIX = "pack:"

SECTION_LIBRARY = "library"
SECTION_DOCS = "docs"
SECTION_CLI = "cli-coverage"
SECTION_FACTORY = "factory"
SECTION_FIELD_MAP = "field-map"
SECTION_BASELINES = "baselines"
SECTION_SIGMETA = "signature-meta"
#: Sections :func:`export_pack` can write (legacy /1).
SECTIONS = (SECTION_LIBRARY, SECTION_DOCS, SECTION_CLI)
#: Sections an import understands.
IMPORT_SECTIONS = SECTIONS + (SECTION_FACTORY, SECTION_FIELD_MAP, SECTION_BASELINES,
                              SECTION_SIGMETA)

KIND_EVIDENCE = "evidence"
KIND_RELEASE_NOTES = "release-notes"
KIND_FIELD_SCHEMAS = "field-schemas"
KIND_FIELD_OVERLAY = "field-overlay"
KIND_CLI = "cli-coverage"
KIND_FACTORY = "factory-wpp"
KIND_FIELD_MAP = "field-map"
KIND_BASELINE = "baseline"
KIND_SIGMETA = "signature-meta"
#: (section, kind) pairs this node imports. Anything else is skipped with a
#: visible warning: a newer publisher may ship a kind an older node lacks.
KINDS = {
    SECTION_LIBRARY: (KIND_EVIDENCE,),
    SECTION_DOCS: (KIND_RELEASE_NOTES, KIND_FIELD_SCHEMAS, KIND_FIELD_OVERLAY),
    SECTION_CLI: (KIND_CLI,),
    SECTION_FACTORY: (KIND_FACTORY,),
    SECTION_FIELD_MAP: (KIND_FIELD_MAP,),
    SECTION_BASELINES: (KIND_BASELINE,),
    SECTION_SIGMETA: (KIND_SIGMETA,),
}
#: The kind of an item that names none (every /1 library and CLI item).
_IMPLICIT_KIND = {SECTION_LIBRARY: KIND_EVIDENCE, SECTION_CLI: KIND_CLI}

#: ``origin_ref`` of every evidence row a pack created. How the node tells its
#: own measurements from imported ones (rule 3) and why export skips them.
ORIGIN_PREFIX = "apipack:"
WITNESS_PREFIX = "witness-"

PACK_NAME_RE = re.compile(r"^satom-apipack-[A-Za-z0-9._-]{1,64}\.tar\.gz$")
_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
#: Keys whose string value is a device name by construction.
_NAME_SLOTS = frozenset({"appliance", "witness"})
#: A harvest ``source``: ``live:fw1@8.0``, ``seed:fw1@8.0.5``, ``default<-fw1@8.0``.
#: ``seed:_default`` (no device) does not match and is left alone.
_SOURCE_WITNESS = re.compile(r"^(?P<pre>[A-Za-z_]+:|default<-)(?P<name>[^@:<]+)(?P<post>@.*)$")

ST_NEW = "new"
ST_PRESENT = "present"
ST_LOCAL = "local"      # the node measured it itself; the pack copy is skipped
ST_UPDATE = "update"    # a copy an older/lower-ranked pack wrote; this one replaces it
ST_REJECTED = "rejected"  # malformed payload: skipped, with the reason
ST_UNKNOWN = "unknown"  # a section/kind this node does not know: skipped, with a warning
IMPORTABLE = (ST_NEW, ST_UPDATE)


class PackError(Exception):
    """Anything that makes a pack unusable. The message is for the operator."""


# ---------------------------------------------------------------------------
# paths
# ---------------------------------------------------------------------------

def data_root() -> Path:
    return Path(current_app.root_path).parent / "data"


def pack_dir() -> Path:
    """Where imported pack artefacts and the import log live."""
    p = Path(current_app.config.get("API_PACK_DIR") or (data_root() / "apipacks"))
    p.mkdir(parents=True, exist_ok=True)
    return p


def shipped_dir() -> Path:
    """``api-packs/`` in the code tree: the pack the release itself carries.

    It arrives the way the code does — ``git clone``/``git pull`` online, the
    bundle's ``app.tar.gz`` offline, an update package's payload — so every node
    has the pack of the release it runs without downloading anything.
    """
    return Path(current_app.config.get("API_PACK_SHIPPED_DIR")
                or (Path(current_app.root_path).parent / "api-packs"))


def upload_dir() -> Path:
    """Packs an operator uploaded through Software Update (a newer pack, or one
    downloaded on its own from the release page)."""
    p = Path(current_app.config.get("API_PACK_UPLOAD_DIR") or (data_root() / "apipack-uploads"))
    p.mkdir(parents=True, exist_ok=True)
    return p


def _schema_root() -> Path:
    from . import field_catalog
    return Path(field_catalog.SCHEMA_ROOT)


def _overlay_path() -> Path:
    return Path(current_app.config.get("FORTIWEB_FIELD_OVERLAY")
                or (data_root() / "fortiweb_field_schema.json"))


def _release_root() -> Path:
    from . import release_corpus
    return release_corpus.root()


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------

def _gz_json(obj) -> bytes:
    # mtime=0: the same content gives the same bytes, so the same sha256.
    return gzip.compress(json.dumps(obj, sort_keys=True, ensure_ascii=False,
                                    default=str).encode("utf-8"),
                         compresslevel=9, mtime=0)


def _read_gz_json(path: Path):
    return json.loads(gzip.decompress(path.read_bytes()).decode("utf-8"))


def _slug(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", str(s or "")).strip("_") or "x"


def _walk_strings(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield str(k)
            yield from _walk_strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _walk_strings(v)


# ---------------------------------------------------------------------------
# identity: what must never leave, and the pseudonyms that replace it
# ---------------------------------------------------------------------------

def _salt() -> bytes:
    """Per-installation secret behind the witness pseudonyms.

    Stable on purpose: the same device gets the same pseudonym in every pack,
    so re-importing a newer pack confirms evidence instead of duplicating it.
    Secret on purpose: an unkeyed hash of a device name or serial could be
    reversed by trying the obvious names.
    """
    p = pack_dir() / "witness.salt"
    if not p.exists():
        fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(secrets.token_hex(32) + "\n")
    return p.read_text().strip().encode("utf-8")


class _Identity:
    """Every device name, serial and address this installation knows about."""

    def __init__(self):
        from ..models import Appliance
        from ..models_backup import ConfigBackup
        names, serials, hosts = set(), set(), set()
        for ev in ApiLibEvidence.query.all():
            names.add(ev.device_name)
            serials.add(ev.device_serial)
            summ = ev.summary or {}
            for w in summ.get("witnesses") or []:
                if isinstance(w, dict):
                    names.add(str(w.get("name") or ""))
        for a in Appliance.query.all():
            names.add(a.name or "")
            serials.add(getattr(a, "serial", "") or "")
            hosts.add(str(getattr(a, "host", "") or ""))
        for b in ConfigBackup.query.all():
            names.add(b.appliance_name or "")
        self.names = {n for n in names if n and not n.startswith(WITNESS_PREFIX)}
        self.serials = {s for s in serials if s and len(s) >= 6}
        self.hosts = {h for h in hosts if h}
        self._nets = {".".join(h.split(".")[:2]) for h in self.hosts if _IPV4.fullmatch(h)}
        self._key = _salt()
        # Long names are also searched INSIDE strings (``fortiweb15@...``);
        # short ones (``fw2``, ``fadc``) only as whole values, or every URN
        # holding the token would be "leaking".
        long_names = sorted((n for n in self.names if len(n) >= 5), key=len, reverse=True)
        self._inner = (re.compile(r"(?<![A-Za-z0-9])(%s)(?![A-Za-z0-9])"
                                  % "|".join(re.escape(n) for n in long_names))
                       if long_names else None)

    def pseudonym(self, product: str, name: str) -> str:
        if not name:
            return ""
        if name.startswith(WITNESS_PREFIX):
            return name
        mac = hmac.new(self._key, ("%s\0%s" % (product, name)).encode("utf-8"),
                       hashlib.sha256).hexdigest()
        return WITNESS_PREFIX + mac[:10]

    def scrub(self, obj, product: str):
        """Replace every known name with its pseudonym; drop serials.

        VALUES only. Keys are endpoint, field and object names: a device that
        happens to be called ``admin`` must not rename the ``admin`` field.
        A key equal to a device name is caught by :meth:`leaks` instead, which
        refuses the export loudly rather than corrupting it quietly.
        """
        if isinstance(obj, dict):
            return {k: self._slot(k, v, product) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self.scrub(v, product) for v in obj]
        if isinstance(obj, str):
            if obj in self.names:
                return self.pseudonym(product, obj)
            if obj in self.serials:
                return ""
            s = obj
            if self._inner is not None:
                s = self._inner.sub(lambda m: self.pseudonym(product, m.group(1)), s)
            for ser in self.serials:
                if ser in s:
                    s = s.replace(ser, "")
            return s
        return obj

    def _learn(self, name: str) -> None:
        """A witness found by POSITION joins the deny-list, so the leak scan
        also catches it anywhere else it was copied to."""
        if name and not name.startswith(WITNESS_PREFIX) and name not in self.names:
            self.names.add(name)
            long_names = sorted((n for n in self.names if len(n) >= 5), key=len, reverse=True)
            self._inner = (re.compile(r"(?<![A-Za-z0-9])(%s)(?![A-Za-z0-9])"
                                      % "|".join(re.escape(n) for n in long_names))
                           if long_names else None)

    def _slot(self, key, value, product: str):
        """Witness slots are pseudonymised by POSITION, whatever the name.

        A deny-list only knows the devices this node still has a row for; the
        first export leaked ``fw1``, a deleted box named only inside a schema
        document. These positions hold a device name by construction.
        """
        if key in _NAME_SLOTS and isinstance(value, str) and value:
            self._learn(value)
            return self.pseudonym(product, value)
        if key == "witnesses" and isinstance(value, list):
            out = []
            for w in value:
                if isinstance(w, str) and w:
                    self._learn(w)
                    out.append(self.pseudonym(product, w))
                elif isinstance(w, dict) and isinstance(w.get("name"), str):
                    self._learn(w["name"])
                    out.append(self.scrub(dict(w, name=self.pseudonym(product, w["name"])), product))
                else:
                    out.append(self.scrub(w, product))
            return out
        if key == "source" and isinstance(value, str):
            m = _SOURCE_WITNESS.match(value)
            if m:
                self._learn(m.group("name"))
                return "%s%s%s" % (m.group("pre"), self.pseudonym(product, m.group("name")),
                                   m.group("post"))
        return self.scrub(value, product)

    def slot_leaks(self, obj, key=None) -> list:
        """Allow-list check of the witness slots: anything there that is not a
        pseudonym is a leak, known name or not."""
        out = []
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k in _NAME_SLOTS and isinstance(v, str) and v and not v.startswith(WITNESS_PREFIX):
                    out.append("%s=%s" % (k, v))
                elif k == "witnesses" and isinstance(v, list):
                    for w in v:
                        n = w.get("name") if isinstance(w, dict) else w
                        if isinstance(n, str) and n and not n.startswith(WITNESS_PREFIX):
                            out.append("witnesses=%s" % n)
                elif k == "source" and isinstance(v, str):
                    m = _SOURCE_WITNESS.match(v)
                    if m and not m.group("name").startswith(WITNESS_PREFIX):
                        out.append("source=%s" % v)
                elif k == "device" and isinstance(v, dict):
                    n = v.get("name")
                    if isinstance(n, str) and n and not n.startswith(WITNESS_PREFIX):
                        out.append("device.name=%s" % n)
                    if v.get("serial") or v.get("appliance_id") is not None:
                        out.append("device carries serial/appliance_id")
                else:
                    out += self.slot_leaks(v, k)
        elif isinstance(obj, list):
            for v in obj:
                out += self.slot_leaks(v, key)
        return out

    def _own_ip(self, s: str) -> str:
        """An IPv4 in ``s`` on one of OUR networks (the /16 of any appliance).

        Not every address: vendor defaults and examples (``0.0.0.0``,
        ``192.168.1.99``) are part of the API knowledge being shipped.
        """
        for m in _IPV4.finditer(s):
            if ".".join(m.group(0).split(".")[:2]) in self._nets:
                return m.group(0)
        return ""

    def leaks(self, obj, *, check_ips: bool) -> list:
        out = []
        for s in _walk_strings(obj):
            if s in self.names or s in self.serials:
                out.append(s)
            elif self._inner is not None and self._inner.search(s):
                out.append(self._inner.search(s).group(1))
            elif any(ser in s for ser in self.serials):
                out.append("serial in %r" % s[:60])
            elif any(h in s for h in self.hosts if len(h) >= 7):
                out.append("address in %r" % s[:60])
            elif check_ips and self._own_ip(s):
                out.append("IPv4 %s" % self._own_ip(s))
        return out


# ---------------------------------------------------------------------------
# export
# ---------------------------------------------------------------------------

def _device_of(ev: ApiLibEvidence) -> dict:
    return {"appliance_id": ev.appliance_id, "name": ev.device_name,
            "serial": ev.device_serial, "model": ev.device_model,
            "hw_type": ev.device_hw_type, "firmware_raw": ev.firmware_raw}


def rebuild_document(ev: ApiLibEvidence):
    """``(doc, "")`` — the normalised evidence document behind one row — or
    ``(None, reason)``.

    ``raw_gz`` is the RAW blob for sweeps (a snapshot with configuration rows),
    legacy matrices and FortiAuthenticator captures, and the document itself
    for the rest. Whatever the path, the result must hash to the stored
    ``sha256``: that is the proof the export says what was measured.
    """
    try:
        raw = json.loads(gzip.decompress(ev.raw_gz).decode("utf-8")) if ev.raw_gz else None
    except (OSError, ValueError) as exc:
        return None, "stored blob is unreadable (%s)" % exc
    if not isinstance(raw, dict):
        return None, "stored blob is not a JSON object"
    candidates = []
    if "endpoints" in raw and "source" in raw:
        candidates = [raw]
    elif ev.source in lib.CLI_SOURCES and isinstance(raw.get("doc"), dict):
        # schema_harvest stores ``{"doc", "tree_text"}``: the document is
        # exported, the raw ``tree`` text (it carries the device prompt) never.
        candidates = [raw["doc"]]
    elif ev.source == lib.SOURCE_SWEEP:
        candidates = [lib.evidence_from_sweep(ev.product, raw, _device_of(ev), ev.origin_ref)]
    elif ev.source == lib.SOURCE_LEGACY:
        candidates = lib.evidence_from_legacy_matrix(ev.product, raw)
    elif "responses" in raw and ev.product == "fortiauthenticator":
        from . import apilib_fac
        candidates = [apilib_fac.evidence_from_capture(raw, _device_of(ev))]
    for doc in candidates:
        if lib.content_hash(doc) == ev.sha256:
            return doc, ""
    if not candidates:
        return None, "no way to re-derive a document from this blob"
    return None, "re-derived document does not reproduce the stored hash"


def _anonymize(doc: dict, ident: _Identity, version: str) -> dict:
    product = doc["product"]
    out = dict(doc)
    dev = doc.get("device") if isinstance(doc.get("device"), dict) else None
    if dev:
        out["device"] = {"name": ident.pseudonym(product, str(dev.get("name") or "")
                                                  or "appliance-%s" % dev.get("appliance_id")),
                         "model": dev.get("model") or "", "hw_type": dev.get("hw_type") or "",
                         "firmware_raw": dev.get("firmware_raw") or ""}
    summ = dict(doc.get("summary") or {})
    if isinstance(summ.get("witnesses"), list):
        summ["witnesses"] = [{k: v for k, v in w.items() if k != "id"}
                             for w in summ["witnesses"] if isinstance(w, dict)]
    out["summary"] = summ
    out["origin_ref"] = "%s%s:%s" % (ORIGIN_PREFIX, version, doc.get("source"))
    out["captured_at"] = str(doc.get("captured_at") or "")[:10]
    return ident.scrub(out, product)


def _scope_label(doc: dict) -> str:
    sc = doc.get("scope") or {}
    if sc.get("kind") == "spans":
        s = doc.get("summary") or {}
        return "%s-%s" % (s.get("min_version") or "?", s.get("max_version") or "?")
    return str(sc.get("version") or sc.get("line") or "")


def _export_library(stage: Path, ident: _Identity, version: str, products) -> tuple:
    items, skipped = [], []
    q = ApiLibEvidence.query.filter_by(healthy=True).order_by(ApiLibEvidence.id)
    for ev in q.all():
        if products and ev.product not in products:
            continue
        if (ev.origin_ref or "").startswith(ORIGIN_PREFIX):
            skipped.append({"evidence_id": ev.id, "reason": "imported from a pack; not ours to re-publish"})
            continue
        doc, why = rebuild_document(ev)
        if doc is not None and doc.get("source") in lib.CLI_SOURCES:
            # Rule 1 again, at the door: a cli_full row holds names only (a
            # default only on lab evidence). A row written around ingest's
            # check is refused here rather than shipped.
            try:
                lib._validate_cli(doc)
            except ValueError as exc:
                doc, why = None, "CLI evidence breaks the names-only rule (%s)" % exc
        if doc is None:
            skipped.append({"evidence_id": ev.id, "product": ev.product,
                            "source": ev.source, "reason": why})
            continue
        clean = _anonymize(doc, ident, version)
        scope = _scope_label(clean)
        rel = "library/%s/%s-%s-%s.json.gz" % (ev.product, ev.source, _slug(scope),
                                              lib.content_hash(clean)[:12])
        (stage / rel).parent.mkdir(parents=True, exist_ok=True)
        (stage / rel).write_bytes(_gz_json(clean))
        eps = clean.get("endpoints") or {}
        items.append({"id": rel[:-len(".json.gz")], "section": SECTION_LIBRARY, "file": rel,
                      "product": ev.product, "source": ev.source,
                      "scope_kind": (clean.get("scope") or {}).get("kind", "build"),
                      "scope": scope, "endpoints": len(eps),
                      "fields": sum(len(e.get("fields") or {}) for e in eps.values()
                                    if isinstance(e, dict)),
                      "witness": (clean.get("device") or {}).get("name", ""),
                      "captured_at": clean.get("captured_at", "")})
    return items, skipped


def _export_docs(stage: Path, ident: _Identity, products) -> tuple:
    from . import release_notes as rn
    items, skipped = [], []

    corpus = rn.load_db(root=_release_root())
    if corpus is not None:
        prods = sorted({i.product for i in corpus.issues} | {s.product for s in corpus.sections})
        for p in prods:
            if products and p not in products:
                continue
            issues = [i.__dict__ for i in corpus.issues if i.product == p]
            sects = [s.__dict__ for s in corpus.sections if s.product == p]
            versions = sorted({r["version"] for r in issues + sects}, key=rn.version_key)
            payload = ident.scrub({"product": p, "generated_at": corpus.generated_at,
                                   "versions": versions, "issues": issues, "sections": sects}, p)
            rel = "docs/release-notes/%s.json.gz" % p
            (stage / rel).parent.mkdir(parents=True, exist_ok=True)
            (stage / rel).write_bytes(_gz_json(payload))
            items.append({"id": rel[:-len(".json.gz")], "section": SECTION_DOCS, "file": rel,
                          "kind": "release-notes", "product": p, "versions": versions,
                          "issues": len(issues), "sections": len(sects)})
    else:
        skipped.append({"kind": "release-notes", "reason": "no release-notes corpus on this node"})

    root = _schema_root()
    for pdir in sorted(root.iterdir()) if root.is_dir() else []:
        if not pdir.is_dir() or (products and pdir.name not in products):
            continue
        for ldir in sorted(pdir.iterdir()):
            if not ldir.is_dir():
                continue
            objs = {}
            for f in sorted(ldir.glob("*.json")):
                try:
                    objs[f.stem] = json.loads(f.read_text(encoding="utf-8"))
                except (OSError, ValueError) as exc:
                    skipped.append({"file": str(f.relative_to(root)), "reason": str(exc)})
            if not objs:
                continue
            rel = "docs/field-schemas/%s/%s.json.gz" % (pdir.name, ldir.name)
            (stage / rel).parent.mkdir(parents=True, exist_ok=True)
            (stage / rel).write_bytes(_gz_json(ident.scrub(objs, pdir.name)))
            items.append({"id": rel[:-len(".json.gz")], "section": SECTION_DOCS, "file": rel,
                          "kind": "field-schemas", "product": pdir.name, "line": ldir.name,
                          "objects": sorted(objs)})

    ov = _overlay_path()
    if ov.is_file() and (not products or "fortiweb" in products):
        rel = "docs/fortiweb-field-overlay.json.gz"
        (stage / rel).parent.mkdir(parents=True, exist_ok=True)
        data = json.loads(ov.read_text(encoding="utf-8"))
        (stage / rel).write_bytes(_gz_json(ident.scrub(data, "fortiweb")))
        items.append({"id": rel[:-len(".json.gz")], "section": SECTION_DOCS, "file": rel,
                      "kind": "field-overlay", "product": "fortiweb"})
    return items, skipped


def _export_cli(stage: Path, ident: _Identity, products) -> tuple:
    """One CLI-coverage digest per (product, version): the newest usable dump.

    Paths, ``set`` NAMES and counts only — never an instance, a value or a line
    of the dump.
    """
    from . import cli_coverage as cc
    items, skipped = [], []
    for product in cc.SUPPORTED_PRODUCTS:
        if products and product not in products:
            continue
        newest: dict = {}
        for rec in cc.evidence_index(product):
            if rec["usable"] and rec.get("version") and rec["version"] not in newest:
                newest[rec["version"]] = rec            # evidence_index is newest first
        for version, rec in sorted(newest.items(), key=lambda kv: fv.sort_key(kv[0])):
            text, rec2 = cc.read_dump(rec["backup_id"])
            if not text:
                skipped.append({"product": product, "version": version,
                                "reason": (rec2 or {}).get("reason") or "unreadable dump"})
                continue
            diff = cc.compare(product, text, line=rec.get("line", ""), version=version)
            keep = ("path", "tokens", "settings", "configured", "catalog", "urn",
                    "channel", "rest_path")
            payload = {
                "product": product, "version": version, "line": rec.get("line", ""),
                "captured_at": (rec.get("created_iso") or "")[:10],
                "witness": ident.pseudonym(product, rec.get("appliance") or ""),
                "counts": diff.get("counts") or {},
                cc.BUCKET_CLI_ONLY: [{k: r[k] for k in keep if k in r}
                                     for r in diff.get(cc.BUCKET_CLI_ONLY) or []],
                cc.BUCKET_CATALOG_GAP: [{k: r[k] for k in keep if k in r}
                                        for r in diff.get(cc.BUCKET_CATALOG_GAP) or []],
                cc.BUCKET_NEAR: [{k: r[k] for k in keep if k in r}
                                 for r in diff.get(cc.BUCKET_NEAR) or []],
            }
            rel = "cli-coverage/%s/%s.json.gz" % (product, _slug(version))
            (stage / rel).parent.mkdir(parents=True, exist_ok=True)
            (stage / rel).write_bytes(_gz_json(ident.scrub(payload, product)))
            items.append({"id": rel[:-len(".json.gz")], "section": SECTION_CLI, "file": rel,
                          "product": product, "version": version,
                          "cli_only": len(payload[cc.BUCKET_CLI_ONLY]),
                          "catalog_gap": len(payload[cc.BUCKET_CATALOG_GAP]),
                          "near_match": len(payload[cc.BUCKET_NEAR])})
    return items, skipped


def _leak_scan(stage: Path, ident: _Identity) -> list:
    found = []
    for f in sorted(stage.rglob("*.json.gz")):
        rel = str(f.relative_to(stage))
        # The release notes are the vendor's own prose and may quote any
        # address; everything else has no business carrying one of ours.
        data = _read_gz_json(f)
        hits = ident.slot_leaks(data) + ident.leaks(
            data, check_ips=not rel.startswith("docs/release-notes/"))
        found += ["%s: %s" % (rel, h) for h in sorted(set(hits))[:5]]
    return found


def _load_signer():
    import importlib.util
    path = Path(__file__).resolve().parents[2] / "deploy" / "sign_update_package.py"
    spec = importlib.util.spec_from_file_location("satom_sign_update_package", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def export_pack(out_dir, version: str, *, products=None, sections=SECTIONS,
                notes: str = "", sign_key=None, passphrase_file=None) -> dict:
    """Build ``satom-apipack-<version>.tar.gz`` in ``out_dir``.

    LEGACY (schema ``satom.api-pack/1``). Kept for local and offline use: one
    node handing its own measurements to another. Since 3.0 the release
    pipeline publishes /2 packs built by satom-harvester and does not call
    this. A /1 pack is verified with the UPDATE trust store, so sign it with a
    key the importing node trusts for updates (an operator's own key), never
    with a pack-lane key.

    Nothing is written to ``out_dir`` unless the leak scan is clean. Unsigned
    unless ``sign_key`` is given; sign later with
    ``deploy/sign_update_package.py sign`` (the same tool as update packages).
    """
    if not _VERSION_RE.match(version or ""):
        raise PackError("invalid pack version %r" % version)
    unknown = set(sections) - set(SECTIONS)
    if unknown:
        raise PackError("unknown section(s): %s" % ", ".join(sorted(unknown)))
    products = set(products or ())
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    name = "satom-apipack-%s" % version
    tmp = Path(tempfile.mkdtemp(prefix="satom-apipack-"))
    try:
        stage = tmp / name
        stage.mkdir()
        ident = _Identity()
        items, skipped = [], []
        for sec, fn in ((SECTION_LIBRARY, lambda: _export_library(stage, ident, version, products)),
                        (SECTION_DOCS, lambda: _export_docs(stage, ident, products)),
                        (SECTION_CLI, lambda: _export_cli(stage, ident, products))):
            if sec in sections:
                i, s = fn()
                items += i
                skipped += s
        if not items:
            raise PackError("nothing to export")
        leaks = _leak_scan(stage, ident)
        if leaks:
            raise PackError("export refused: identifying data survived the scrub — "
                            + "; ".join(leaks[:8]))
        files = {}
        for f in sorted(stage.rglob("*")):
            if f.is_file():
                files[str(f.relative_to(stage))] = {"sha256": up.sha256_file(f),
                                                    "size": f.stat().st_size}
        manifest = {"schema": SCHEMA, "product": PRODUCT, "version": version,
                    "built_at": datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
                    "sections": [s for s in SECTIONS if s in sections],
                    "items": items, "files": files, "notes": str(notes or "")}
        (stage / "manifest.json").write_bytes(up.dump_manifest(manifest))
        signed_by = None
        if sign_key:
            signer = _load_signer()
            pw = signer._passphrase_from_file(passphrase_file) if passphrase_file else None
            seed = signer.load_private_seed(Path(sign_key), pw)
            signed_by = signer._sign_dir(stage, seed)
        target = out_dir / ("%s.tar.gz" % name)
        part = out_dir / (".%s.tar.gz.part" % name)
        with tarfile.open(part, "w:gz") as tf:
            tf.add(stage, arcname=name)
        os.replace(part, target)
        sha = up.sha256_file(target)
        (out_dir / ("%s.tar.gz.sha256" % name)).write_text("%s  %s\n" % (sha, target.name))
        return {"path": str(target), "sha256": sha, "items": len(items),
                "by_section": {s: sum(1 for i in items if i["section"] == s) for s in SECTIONS},
                "signed_by": signed_by, "skipped": skipped}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------------------
# trust: which keys may sign which pack (C2)
# ---------------------------------------------------------------------------

def tree_key_dir() -> Path:
    """``deploy/pack-keys`` in the code tree: the lane keys the release ships.

    Found beside this module, not through a setting an attacker could move.
    The tree arrives release-signed (update package) or from the release
    clone, so these keys are trusted transitively — and because they come
    WITH the code, a /2 pack in ``api-packs/`` imports on a fresh install and
    on the first update without any key having been installed first."""
    return Path(current_app.config.get("API_PACK_TREE_KEY_DIR")
                or (Path(__file__).resolve().parents[2] / "deploy" / "pack-keys"))


def operator_key_dir() -> Path:
    """``/etc/satom/pack-keys``: lane keys an operator added (rotation, a fork's
    own publisher). Root-owned like the update trust store."""
    return Path(current_app.config.get("API_PACK_KEY_DIR")
                or os.environ.get("SATOM_PACK_KEY_DIR") or up.PACK_KEY_DIR)


def lane_key_dirs(lane: str) -> list:
    if lane not in LANES:
        raise PackError("no key set for lane %r" % lane)
    return [tree_key_dir() / lane, operator_key_dir() / lane]


def lane_keys(lane: str) -> list:
    """Every key trusted for ``lane``. An operator directory that exists but
    is not root-owned is refused (anyone who can write it can mint packs); a
    missing one is simply empty."""
    tree, oper = lane_key_dirs(lane)
    if oper.exists():
        problem = up.trust_store_problem(str(oper))
        if problem:
            raise PackError("pack key directory is not safe to use: %s" % problem)
    return up.load_key_dirs([tree, oper])


def trust_summary() -> dict:
    """``{purpose: [key...]}`` for the page and ``show apipack``."""
    out = {"update": [dict(k, dir=str(TRUST_DIR)) for k in up.load_trust_store(TRUST_DIR)]}
    for lane in LANES:
        try:
            out[lane] = lane_keys(lane)
        except PackError:
            out[lane] = []
    return {p: [{"fingerprint": k["fingerprint"], "comment": k.get("comment", ""),
                 "name": k["name"], "dir": k.get("dir", "")} for k in ks]
            for p, ks in out.items()}


# ---------------------------------------------------------------------------
# verify + inspect
# ---------------------------------------------------------------------------

def _satom_version() -> str:
    from ..version import app_version
    return app_version()


def _legacy_lane(version: str) -> str:
    """The lane a /1 pack's content belongs to: ``kb-*`` was the knowledge
    series, every other /1 pack was the release's own (the api_pack lineage)."""
    return LANE_KNOWLEDGE if str(version or "").startswith(KNOWLEDGE_PREFIX) else LANE_API_PACK


def _manifest_meta(manifest: dict) -> dict:
    """What the manifest says about the pack as a whole, validated.

    ``lane`` is the PROVENANCE lane (a /1 pack maps onto one, see
    :func:`_legacy_lane`); ``series`` follows :func:`pack_series`."""
    version = manifest.get("version")
    if not isinstance(version, str) or not _VERSION_RE.match(version):
        raise PackError("pack manifest has no valid version (%r)" % (version,))
    schema = manifest.get("schema")
    meta = {"schema": schema, "version": version, "name": "satom-apipack-%s" % version,
            "min_satom": "", "publisher": "", "content_fingerprint": "", "snapshot": {},
            "pinned_to": ""}
    if schema == SCHEMA_V2:
        missing = [k for k in V2_REQUIRED if k not in manifest]
        if missing:
            raise PackError("pack manifest (%s) lacks required key(s): %s"
                            % (SCHEMA_V2, ", ".join(missing)))
        for k in ("min_satom", "publisher", "content_fingerprint", "pinned_to"):
            if not isinstance(manifest.get(k), str):
                raise PackError("pack manifest key %r must be a string" % k)
        if not up.VERSION_RE.match(manifest["min_satom"]):
            raise PackError("pack manifest min_satom %r is not a version" % manifest["min_satom"])
        snap = manifest.get("snapshot")
        if not isinstance(snap, dict):
            raise PackError("pack manifest key 'snapshot' must be an object")
        if not isinstance(manifest.get("sections"), list):
            raise PackError("pack manifest key 'sections' must be a list")
        meta.update({k: manifest[k] for k in ("min_satom", "publisher", "content_fingerprint",
                                              "pinned_to")})
        meta["snapshot"] = snap
        meta["lane"] = manifest["lane"]
        meta["series"] = manifest["lane"]
    else:
        meta["lane"] = _legacy_lane(version)
        meta["series"] = SERIES_KNOWLEDGE if version.startswith(KNOWLEDGE_PREFIX) else SERIES_RELEASE
    meta["provenance"] = "%s%s:%s" % (PROV_PREFIX, meta["lane"], meta["name"])
    return meta


def _verify(pkg: Path, manifest: dict, trust_dir) -> dict:
    """The key that signed ``pkg``, checked against the ONE key set its schema
    and lane allow. ``manifest`` is read before it is trusted, but only to pick
    the key set: the lane is inside the signed bytes, so changing it breaks the
    signature for every key set but the one an attacker would need anyway."""
    schema = manifest.get("schema")
    if schema == SCHEMA_V2:
        lane = manifest.get("lane")
        if lane == LANE_TRANSPORT:
            raise PackError("this is a harvester TRANSPORT pack (lane 'harvester'): it only "
                            "travels from satom-harvester to the publisher and is never "
                            "imported. Import the api_pack or knowledge pack published from it.")
        if lane not in LANES:
            raise PackError("pack lane %r is not importable: SATOM imports only %s packs"
                            % (lane, " and ".join(LANES)))
        keys = lane_keys(lane)
        if not keys:
            raise PackError("no %s key is trusted on this node (%s); install one with "
                            "'satom execute trust add-key --purpose %s <file.pub>'"
                            % (lane, " + ".join(str(d) for d in lane_key_dirs(lane)), lane))
        try:
            return up.verify_signature_keys(pkg, keys, "%s pack keys" % lane)
        except up.PackageError as exc:
            if "no key in the trust store" not in str(exc):
                raise
            raise PackError("this %s pack is not signed by a trusted %s key (%d key(s) "
                            "tried). A pack signed with another lane's key or with the "
                            "release key is refused." % (lane, lane, len(keys)))
    if schema == SCHEMA_V1:
        problem = up.trust_store_problem(trust_dir)
        if problem:
            raise PackError("trust store is not safe to use: %s" % problem)
        return up.verify_signature(pkg, trust_dir)
    raise PackError("unsupported pack schema %r (this node speaks %s)"
                    % (schema, ", ".join(SCHEMAS)))


def _open(path, tmp: Path, trust_dir) -> tuple:
    """``(pkg_dir, manifest, key, meta)`` of a verified pack, or PackError."""
    path = Path(path)
    if not PACK_NAME_RE.match(path.name):
        raise PackError("%r is not an API pack name (satom-apipack-<version>.tar.gz)" % path.name)
    try:
        pkg = up.extract_package(path, tmp)
        manifest = up.read_manifest(pkg)
        key = _verify(pkg, manifest, trust_dir)
    except up.PackageError as exc:
        raise PackError(str(exc))
    if manifest.get("product") != PRODUCT:
        raise PackError("pack is for product %r, not %s" % (manifest.get("product"), PRODUCT))
    meta = _manifest_meta(manifest)
    mine = _satom_version()
    if meta["min_satom"] and up.compare_versions(meta["min_satom"], mine) > 0:
        raise PackError("pack %s needs SATOM %s or newer; this node runs %s. Update SATOM "
                        "first, then import the pack again. Nothing was imported."
                        % (meta["name"], meta["min_satom"], mine))
    problems = up.verify_contents(pkg, manifest)
    if problems:
        raise PackError("pack contents do not match the signed manifest: %s"
                        % "; ".join(problems[:5]))
    items = manifest.get("items")
    if not isinstance(items, list):
        raise PackError("pack manifest lists no items")
    for it in items:
        if not isinstance(it, dict) or not all(isinstance(it.get(k), str) and it.get(k)
                                               for k in ("id", "section", "file")):
            raise PackError("pack manifest holds an item without id/section/file: %r"
                            % (str(it)[:120],))
        if it.get("file") not in (manifest.get("files") or {}):
            raise PackError("item %s names a file the manifest does not sign" % it.get("id"))
    return pkg, manifest, key, meta


class ItemInvalid(ValueError):
    """A malformed item payload. The item is rejected; the import goes on."""


_PRODUCT_RE = re.compile(r"^[a-z][a-z0-9_-]{1,31}$")
_PATH_TOKEN_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$")


def _token(value, what: str, rx=_PATH_TOKEN_RE) -> str:
    """A string safe to use as ONE path component, or ItemInvalid."""
    if not isinstance(value, str) or not rx.match(value) or ".." in value:
        raise ItemInvalid("%s %r is not a valid name" % (what, value if isinstance(value, str)
                                                         else type(value).__name__))
    return value


def _product_of(it: dict, data=None) -> str:
    p = it.get("product")
    if not p and isinstance(data, dict):
        p = data.get("product")
    p = _token(p, "product", _PRODUCT_RE)
    if isinstance(data, dict) and data.get("product") not in (None, "", p):
        raise ItemInvalid("payload product %r does not match the item's %r"
                          % (data.get("product"), p))
    return p


def _canon_sha(obj) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, ensure_ascii=False, default=str,
                                     separators=(",", ":")).encode("utf-8")).hexdigest()


def provenance_parts(prov: str) -> tuple:
    """``(lane, pack name)`` of ``pack:<lane>:<name>``; ``("local", "")``."""
    if not prov or not str(prov).startswith(PROV_PREFIX):
        return PROV_LOCAL, ""
    rest = str(prov)[len(PROV_PREFIX):]
    lane, _, name = rest.partition(":")
    return lane, name


def _version_key_of(name: str):
    return _pack_version_key("%s.tar.gz" % name) if name.startswith("satom-apipack-") \
        else ((1, 0, name),)


def outranks(meta: dict, current: str) -> tuple:
    """``(may_replace, why_not)``: may the pack ``meta`` replace a copy whose
    provenance is ``current``? Local data is never replaced; between packs the
    higher lane wins (api_pack > knowledge) and inside a lane the newer pack."""
    lane, name = provenance_parts(current)
    if lane == PROV_LOCAL:
        return False, "this node's own copy; a pack never replaces it"
    mine, theirs = LANE_RANK.get(meta["lane"], 0), LANE_RANK.get(lane, 0)
    if mine != theirs:
        return (mine > theirs,
                "" if mine > theirs else "kept: written by %s (%s outranks %s)"
                % (current, lane, meta["lane"]))
    if _version_key_of(meta["name"]) >= _version_key_of(name):
        return True, ""
    return False, "kept: written by the newer pack %s" % name


def evidence_provenance(origin_ref: str) -> str:
    """Provenance of an evidence row from its ``origin_ref``."""
    o = origin_ref or ""
    if not o.startswith(ORIGIN_PREFIX):
        return PROV_LOCAL
    parts = o[len(ORIGIN_PREFIX):].split(":")
    if len(parts) >= 3 and parts[0] in LANES:
        return "%s%s:%s" % (PROV_PREFIX, parts[0], parts[1])
    ver = parts[0]
    return "%s%s:satom-apipack-%s" % (PROV_PREFIX, _legacy_lane(ver), ver)


class _Ledger:
    """Who wrote each file-backed copy (release notes per version, field
    schema per object, the overlay, CLI digests): ``apipacks/provenance.json``.

    A copy with no entry is LOCAL — unless the import log of a 2.x import says
    a pack wrote it (those imports predate the ledger)."""

    NAME = "provenance.json"

    def __init__(self):
        self.path = pack_dir() / self.NAME
        try:
            self.data = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(self.data, dict):
                self.data = {}
        except (OSError, ValueError):
            self.data = {}
        self._legacy = None
        self.dirty = False

    def provenance(self, key: str, unowned: str = PROV_LOCAL) -> str:
        rec = self.data.get(key)
        if isinstance(rec, dict) and rec.get("provenance"):
            return rec["provenance"]
        return self.legacy().get(key) or unowned

    def set(self, key: str, provenance: str) -> None:
        self.data[key] = {"provenance": provenance,
                          "at": datetime.utcnow().replace(microsecond=0).isoformat() + "Z"}
        self.dirty = True

    def save(self) -> None:
        if not self.dirty:
            return
        tmp = self.path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(self.data, indent=1, sort_keys=True), encoding="utf-8")
        os.replace(tmp, self.path)
        self.dirty = False

    def legacy(self) -> dict:
        if self._legacy is None:
            self._legacy = _legacy_owners()
        return self._legacy


def _legacy_owners() -> dict:
    """``{ledger key: provenance}`` reconstructed from the import logs a 2.x
    node wrote: what each logged import added. Oldest first, first writer wins
    (a 2.x import only ever added)."""
    out: dict = {}
    d = pack_dir() / "imports"
    for f in sorted(d.glob("*.json")) if d.is_dir() else []:
        try:
            rec = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(rec, dict) or rec.get("lane"):
            continue        # 3.0 logs: the ledger itself is authoritative
        ver = str(rec.get("version") or "")
        prov = "%s%s:satom-apipack-%s" % (PROV_PREFIX, _legacy_lane(ver), ver)
        for it in rec.get("items") or []:
            res = it.get("result") if isinstance(it, dict) else None
            if not isinstance(res, dict) or not it.get("imported"):
                continue
            iid, product = str(it.get("id") or ""), str(it.get("product") or "")
            if iid.startswith("docs/release-notes/"):
                for v in res.get("versions") or []:
                    out.setdefault("release-notes/%s/%s" % (product, v), prov)
            elif iid.startswith("docs/field-schemas/"):
                line = iid.rsplit("/", 1)[-1]
                for o in res.get("objects") or []:
                    out.setdefault("field-schemas/%s/%s/%s" % (product, line, o), prov)
            elif iid == "docs/fortiweb-field-overlay":
                out.setdefault("field-overlay/fortiweb", prov)
    return out


class _Run:
    """One inspect or import of one pack: what it is and whose copies it meets."""

    def __init__(self, pkg: Path, meta: dict):
        self.pkg = pkg
        self.meta = meta
        self.provenance = meta["provenance"]
        self.ledger = _Ledger()
        self.cache: dict = {}
        built = (meta.get("snapshot") or {}).get("built_at") or ""
        try:
            self.built_at = datetime.fromisoformat(str(built).replace("Z", "")[:19])
        except ValueError:
            self.built_at = datetime.utcnow().replace(microsecond=0)

    def read(self, it: dict):
        try:
            return _read_gz_json(self.pkg / it["file"])
        except (OSError, ValueError, EOFError) as exc:
            raise ItemInvalid("payload is not gzip JSON (%s)" % exc)

    def claim(self, key: str, current_sha, new_sha: str, *, unowned: str = PROV_LOCAL) -> dict:
        """State of one replaceable copy (C6). ``current_sha`` None = absent."""
        if current_sha is None:
            return {"state": ST_NEW}
        prov = self.ledger.provenance(key, unowned)
        if current_sha == new_sha:
            return {"state": ST_PRESENT, "current": prov}
        if prov == PROV_LOCAL:
            return {"state": ST_LOCAL, "current": prov,
                    "note": "this node's own copy; a pack never replaces it"}
        ok, why = outranks(self.meta, prov)
        if ok:
            return {"state": ST_UPDATE, "current": prov}
        return {"state": ST_PRESENT, "current": prov, "note": why}


def _rollup(states: dict, extra: dict | None = None) -> dict:
    """Item state from per-unit states (versions, objects, rows)."""
    out = dict(extra or {})
    for k in (ST_NEW, ST_UPDATE, ST_LOCAL, ST_PRESENT):
        out["%s_units" % k] = sorted(u for u, s in states.items() if s == k)
    if out["new_units"]:
        out["state"] = ST_NEW
    elif out["update_units"]:
        out["state"] = ST_UPDATE
    elif out["local_units"] and not out["present_units"]:
        out["state"] = ST_LOCAL
    else:
        out["state"] = ST_PRESENT
    return out


def _local_build(product: str, scope: dict) -> ApiLibBuild | None:
    v = scope.get("version") or scope.get("line")
    return lib._build_row(product, v) if v else None


def _library_state(doc: dict) -> str:
    sha = lib.content_hash(doc)
    if ApiLibEvidence.query.filter_by(product=doc["product"], source=doc["source"],
                                      sha256=sha).first() is not None:
        return ST_PRESENT
    # Vendor claims are the same document everywhere (no witness), so the hash
    # above already answers for them. Anything a device produced is skipped
    # when this node holds its OWN evidence of the same kind for that build.
    # A LAB measurement (a knowledge pack's fresh rows, ``summary.lab``) is
    # imported even next to this node's own evidence of the build: it only adds
    # what a production box cannot show (fields of tables it has empty), the
    # build's schema is the same on every box, and facts only ever accumulate.
    lab = bool((doc.get("summary") or {}).get("lab"))
    if doc["source"] != lib.SOURCE_VENDOR and not lab:
        b = _local_build(doc["product"], doc.get("scope") or {})
        if b is not None:
            from .schema_harvest import ORIGIN_PREFIX as _PARTIAL
            own = (ApiLibEvidence.query
                   .filter_by(product=doc["product"], source=doc["source"],
                              build_id=b.id, healthy=True)
                   .filter(~ApiLibEvidence.origin_ref.startswith(ORIGIN_PREFIX))
                   # A schema harvest's REST probe is partial: it does not
                   # make this node's own measurement of the build complete.
                   .filter(~ApiLibEvidence.origin_ref.startswith(_PARTIAL))
                   .first())
            if own is not None:
                return ST_LOCAL
    return ST_NEW


# -- per kind: validate the payload, say what importing it would do ----------

def _v_library(run: _Run, it: dict):
    doc = run.read(it)
    if not isinstance(doc, dict):
        raise ItemInvalid("evidence document is not an object")
    if doc.get("product") != it.get("product") and it.get("product"):
        raise ItemInvalid("evidence product %r does not match the item's %r"
                          % (doc.get("product"), it.get("product")))
    if doc.get("source") not in lib.SOURCES:
        raise ItemInvalid("unknown evidence source %r" % (doc.get("source"),))
    try:
        lib._validate(doc)
        if doc.get("source") in lib.CLI_SOURCES:
            lib._validate_cli(doc)
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        raise ItemInvalid("evidence document refused: %s" % exc)
    return doc


def _s_library(run: _Run, it: dict, doc) -> dict:
    st = _library_state(doc)
    out = {"state": st}
    if st == ST_PRESENT:
        ev = ApiLibEvidence.query.filter_by(product=doc["product"], source=doc["source"],
                                            sha256=lib.content_hash(doc)).first()
        out["current"] = evidence_provenance(ev.origin_ref if ev else "")
    elif st == ST_LOCAL:
        out["current"] = PROV_LOCAL
    return out


def _rn_row(cls, d: dict, product: str) -> dict:
    return dict({k: d.get(k) for k in cls.__annotations__ if k in d}, product=product)


def _v_release_notes(run: _Run, it: dict):
    from . import release_notes as rn
    data = run.read(it)
    if not isinstance(data, dict):
        raise ItemInvalid("release notes payload is not an object")
    product = _product_of(it, data)
    by_v: dict = {}
    for key, cls in (("issues", rn.ReleaseIssue), ("sections", rn.ReleaseSection)):
        rows = data.get(key) or []
        if not isinstance(rows, list):
            raise ItemInvalid("release notes %r is not a list" % key)
        for d in rows:
            if not isinstance(d, dict) or not isinstance(d.get("version"), str) \
                    or not d["version"]:
                raise ItemInvalid("a release-notes row has no version")
            if (d.get("product") or product) != product:
                continue        # rows of another product never land under this one
            try:
                row = cls(**_rn_row(cls, d, product)).__dict__
            except TypeError as exc:
                raise ItemInvalid("a release-notes %s row is incomplete (%s)" % (key[:-1], exc))
            by_v.setdefault(d["version"], {"issues": [], "sections": []})[key].append(row)
    if not by_v:
        raise ItemInvalid("release notes item carries no row for %s" % product)
    return {"product": product, "versions": by_v,
            "generated_at": str(data.get("generated_at") or "")}


def _rn_sha(rows: dict) -> str:
    return _canon_sha({k: sorted(json.dumps(r, sort_keys=True, default=str) for r in rows[k])
                       for k in ("issues", "sections")})


def _rn_current(run: _Run) -> dict:
    """``{(product, version): sha}`` of the local corpus (cached per run)."""
    if "rn" not in run.cache:
        from . import release_notes as rn
        corpus = rn.load_db(root=_release_root())
        cur: dict = {}
        if corpus is not None:
            for key, rows, cls in (("issues", corpus.issues, rn.ReleaseIssue),
                                   ("sections", corpus.sections, rn.ReleaseSection)):
                for r in rows:
                    d = r.__dict__
                    cur.setdefault((d.get("product"), d.get("version")),
                                   {"issues": [], "sections": []})[key].append(
                        _rn_row(cls, d, d.get("product")))
        run.cache["rn"] = {k: _rn_sha(v) for k, v in cur.items()}
    return run.cache["rn"]


def _s_release_notes(run: _Run, it: dict, p: dict) -> dict:
    from . import release_notes as rn
    cur = _rn_current(run)
    states, notes = {}, {}
    for v, rows in p["versions"].items():
        c = run.claim("release-notes/%s/%s" % (p["product"], v), cur.get((p["product"], v)),
                      _rn_sha(rows))
        states[v] = c["state"]
        if c.get("note"):
            notes[v] = c["note"]
    out = _rollup(states, {"versions": sorted(p["versions"], key=rn.version_key)})
    out["new_versions"] = out["new_units"]
    out["update_versions"] = out["update_units"]
    if notes:
        out["notes"] = notes
        out["note"] = "; ".join(sorted(set(notes.values())))[:300]
    return out


def _schema_line_dir(product: str, line: str) -> Path:
    return _schema_root() / product / line


def _v_field_schemas(run: _Run, it: dict):
    data = run.read(it)
    if not isinstance(data, dict) or not data:
        raise ItemInvalid("field-schemas payload is not a non-empty object")
    product = _product_of(it)
    line = _token(it.get("line"), "line")
    objs, bad = {}, []
    for o, body in data.items():
        if isinstance(o, str) and _PATH_TOKEN_RE.match(o) and ".." not in o \
                and isinstance(body, (dict, list)):
            objs[o] = body
        else:
            bad.append(str(o)[:60])
    if not objs:
        raise ItemInvalid("no valid object in the field-schemas payload")
    return {"product": product, "line": line, "objects": objs, "bad": bad}


def _file_sha(path: Path):
    if not path.is_file():
        return None
    try:
        return _canon_sha(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, ValueError):
        return "unreadable"


def _s_field_schemas(run: _Run, it: dict, p: dict) -> dict:
    d = _schema_line_dir(p["product"], p["line"])
    states, notes = {}, {}
    for o, body in p["objects"].items():
        c = run.claim("field-schemas/%s/%s/%s" % (p["product"], p["line"], o),
                      _file_sha(d / ("%s.json" % o)), _canon_sha(body))
        states[o] = c["state"]
        if c.get("note"):
            notes[o] = c["note"]
    out = _rollup(states, {"objects": sorted(p["objects"]), "line": p["line"]})
    out["new_objects"] = out["new_units"]
    out["update_objects"] = out["update_units"]
    if p["bad"]:
        out["warning"] = "skipped invalid object name(s): %s" % ", ".join(p["bad"][:10])
    if notes:
        out["notes"] = notes
        out["note"] = "; ".join(sorted(set(notes.values())))[:300]
    return out


def _v_overlay(run: _Run, it: dict):
    data = run.read(it)
    if not isinstance(data, dict):
        raise ItemInvalid("field overlay payload is not an object")
    return data


def _s_overlay(run: _Run, it: dict, data) -> dict:
    return run.claim("field-overlay/fortiweb", _file_sha(_overlay_path()), _canon_sha(data))


def _cli_dest(product: str, version: str) -> Path:
    return pack_dir() / "cli-coverage" / product / ("%s.json" % _slug(version))


def _v_cli(run: _Run, it: dict):
    data = run.read(it)
    if not isinstance(data, dict):
        raise ItemInvalid("cli-coverage payload is not an object")
    product = _product_of(it, data)
    version = it.get("version") or data.get("version")
    if not isinstance(version, str) or not _VERSION_RE.match(version):
        raise ItemInvalid("cli-coverage item has no valid version (%r)" % (version,))
    from . import cli_coverage as cc
    for b in (cc.BUCKET_CLI_ONLY, cc.BUCKET_CATALOG_GAP, cc.BUCKET_NEAR):
        rows = data.get(b, [])
        if not isinstance(rows, list) or not all(isinstance(r, dict) for r in rows):
            raise ItemInvalid("cli-coverage %r is not a list of objects" % b)
    if not isinstance(data.get("counts", {}), dict):
        raise ItemInvalid("cli-coverage 'counts' is not an object")
    return {"product": product, "version": version, "data": data}


def _s_cli(run: _Run, it: dict, p: dict) -> dict:
    # A digest only ever comes from a pack, so one without a ledger entry was
    # written by a 2.x import: any pack may refresh it.
    return run.claim("cli-coverage/%s/%s" % (p["product"], _slug(p["version"])),
                     _file_sha(_cli_dest(p["product"], p["version"])), _canon_sha(p["data"]),
                     unowned="%slegacy:" % PROV_PREFIX)


def _handlers() -> dict:
    from . import api_pack_kinds as k
    return {
        KIND_EVIDENCE: (_v_library, _s_library, _i_library),
        KIND_RELEASE_NOTES: (_v_release_notes, _s_release_notes, _i_release_notes),
        KIND_FIELD_SCHEMAS: (_v_field_schemas, _s_field_schemas, _i_field_schemas),
        KIND_FIELD_OVERLAY: (_v_overlay, _s_overlay, _i_overlay),
        KIND_CLI: (_v_cli, _s_cli, _i_cli),
        KIND_FACTORY: (k.validate_factory, k.state_factory, k.import_factory),
        KIND_FIELD_MAP: (k.validate_field_map, k.state_field_map, k.import_field_map),
        KIND_BASELINE: (k.validate_baseline, k.state_baseline, k.import_baseline),
        KIND_SIGMETA: (k.validate_sigmeta, k.state_sigmeta, k.import_sigmeta),
    }


def item_kind(it: dict) -> str:
    return it.get("kind") or _IMPLICIT_KIND.get(it.get("section"), "")


def _item_state(run: _Run, it: dict) -> tuple:
    """``(state dict, payload)``. Never raises for a bad item: an unknown
    section/kind or a malformed payload becomes a visible warning."""
    sec, kind = it["section"], item_kind(it)
    if kind not in KINDS.get(sec, ()):
        return ({"state": ST_UNKNOWN,
                 "warning": "unknown %s %r in section %r: skipped (this SATOM does not "
                            "import it; a newer one may)"
                            % ("kind" if sec in KINDS else "section", kind or None, sec)},
                None)
    validate, state, _imp = _handlers()[kind]
    try:
        payload = validate(run, it)
        st = state(run, it, payload)
    except ItemInvalid as exc:
        return {"state": ST_REJECTED, "warning": "malformed %s item: %s" % (kind, exc)}, None
    return st, payload


def _public(st: dict) -> dict:
    """State fields worth showing (inspect, results): drop the bulky unit lists."""
    return {k: v for k, v in st.items() if not k.endswith("_units") or k == "update_units"}


def _pack_info(meta: dict, key: dict) -> dict:
    return {"schema": meta["schema"], "lane": meta["lane"], "series": meta["series"],
            "provenance": meta["provenance"], "min_satom": meta["min_satom"],
            "pinned_to": meta["pinned_to"], "publisher": meta["publisher"],
            "content_fingerprint": meta["content_fingerprint"],
            "snapshot": meta["snapshot"],
            "signed_by": {"fingerprint": key.get("fingerprint"),
                          "comment": key.get("comment", "")}}


def _warnings(items: list) -> list:
    return ["%s: %s" % (it["id"], it["warning"]) for it in items if it.get("warning")]


def inspect_pack(path, trust_dir=None) -> dict:
    """Verify a pack and say, per item, what importing it would do."""
    tmp = Path(tempfile.mkdtemp(prefix="satom-apipack-"))
    try:
        pkg, manifest, key, meta = _open(path, tmp, trust_dir or TRUST_DIR)
        run = _Run(pkg, meta)
        items = []
        for it in manifest["items"]:
            st, _payload = _item_state(run, it)
            items.append(dict(it, kind=item_kind(it) or it.get("kind"), **_public(st)))
        return dict(_pack_info(meta, key), version=manifest.get("version"),
                    built_at=manifest.get("built_at"), notes=manifest.get("notes", ""),
                    items=items, warnings=_warnings(items))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------------------
# import
# ---------------------------------------------------------------------------

def _selected(it: dict, products, sections, ids) -> bool:
    if ids:
        return it["id"] in ids
    if products and it.get("product") not in products:
        return False
    if sections and it["section"] not in sections:
        return False
    return True


def _i_library(run: _Run, it: dict, doc, st: dict) -> dict:
    doc = dict(doc, origin_ref="%s%s:%s:%s" % (ORIGIN_PREFIX, run.meta["lane"],
                                                run.meta["name"], doc.get("source")))
    res = lib.ingest(doc)
    return {"evidence_id": res["evidence_id"], "created": res["created"]}


def _i_release_notes(run: _Run, it: dict, p: dict, st: dict) -> dict:
    """Add the item's new versions of ONE product to the local corpus and
    replace the pack-owned versions it corrects. Rows are taken only if they
    belong to the item's product: FortiWeb, FortiAnalyzer and FortiGate all
    ship 7.6.x / 8.0.x, so a version match alone would let a row of one
    product land as another's."""
    from . import release_notes as rn
    new, upd = list(st.get("new_units") or []), list(st.get("update_units") or [])
    want = set(new) | set(upd)
    product = p["product"]
    root = _release_root()
    corpus = rn.load_db(root=root) or rn.ReleaseNotesDB(generated_at=p["generated_at"])
    if upd:
        drop = {(product, v) for v in upd}
        corpus.issues = [i for i in corpus.issues if (i.product, i.version) not in drop]
        corpus.sections = [s for s in corpus.sections if (s.product, s.version) not in drop]
    issues = [rn.ReleaseIssue(**d) for v in sorted(want) for d in p["versions"][v]["issues"]]
    sects = [rn.ReleaseSection(**d) for v in sorted(want) for d in p["versions"][v]["sections"]]
    corpus.issues += issues
    corpus.sections += sects
    corpus.versions = sorted(set(corpus.versions) | want, key=rn.version_key)
    rn.save_db(corpus, root=root)
    for v in want:
        run.ledger.set("release-notes/%s/%s" % (product, v), run.provenance)
    run.cache.pop("rn", None)
    return {"versions": sorted(want, key=rn.version_key),
            "replaced": sorted(upd, key=rn.version_key),
            "issues": len(issues), "sections": len(sects)}


def _write_json(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(".%s.tmp" % path.name)
    tmp.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, path)


def _i_field_schemas(run: _Run, it: dict, p: dict, st: dict) -> dict:
    d = _schema_line_dir(p["product"], p["line"])
    written, replaced = [], []
    for o in list(st.get("new_units") or []) + list(st.get("update_units") or []):
        _write_json(d / ("%s.json" % o), p["objects"][o])
        run.ledger.set("field-schemas/%s/%s/%s" % (p["product"], p["line"], o), run.provenance)
        (replaced if o in (st.get("update_units") or []) else written).append(o)
    return {"objects": written, "replaced": replaced}


def _i_overlay(run: _Run, it: dict, data, st: dict) -> dict:
    p = _overlay_path()
    _write_json(p, data)
    run.ledger.set("field-overlay/fortiweb", run.provenance)
    from . import fortiweb_field_schema
    fortiweb_field_schema._overlay.cache_clear()
    return {"written": str(p.name), "replaced": st["state"] == ST_UPDATE}


def _i_cli(run: _Run, it: dict, p: dict, st: dict) -> dict:
    dest = _cli_dest(p["product"], p["version"])
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(p["data"], indent=1, ensure_ascii=False), encoding="utf-8")
    run.ledger.set("cli-coverage/%s/%s" % (p["product"], _slug(p["version"])), run.provenance)
    return {"written": str(dest.relative_to(pack_dir()))}


def _import_one(run: _Run, it: dict, st: dict, payload) -> dict:
    return _handlers()[item_kind(it)][2](run, it, payload, st)


def import_pack(path, *, trust_dir=None, products=None, sections=None, ids=None,
                dry_run: bool = False, actor: str = "", progress=None) -> dict:
    """Verify, then import the selected items that are ``new`` or ``update``.

    ``present`` and ``local`` items are reported and never touched (rule 3);
    ``rejected`` (malformed) and ``unknown`` (a kind this node does not know)
    items are skipped with a warning and do not fail the import. Every run that
    imports something is logged under ``apipacks/imports/``.
    ``progress(done, total, item_id)`` is called before each selected item, and
    once more with ``item_id=None`` when the last one is finished.
    """
    products, sections, ids = set(products or ()), set(sections or ()), set(ids or ())
    tmp = Path(tempfile.mkdtemp(prefix="satom-apipack-"))
    try:
        pkg, manifest, key, meta = _open(path, tmp, trust_dir or TRUST_DIR)
        known = {it["id"] for it in manifest["items"]}
        if ids - known:
            raise PackError("not in this pack: %s" % ", ".join(sorted(ids - known)))
        run = _Run(pkg, meta)
        results = []
        chosen = [it for it in manifest["items"] if _selected(it, products, sections, ids)]
        for n, it in enumerate(chosen):
            if progress:
                progress(n, len(chosen), it["id"])
            st, payload = _item_state(run, it)
            rec = {"id": it["id"], "section": it["section"], "kind": item_kind(it),
                   "product": it.get("product"), "state": st["state"]}
            for k in ("warning", "current", "note"):
                if st.get(k):
                    rec[k] = st[k]
            if st["state"] in IMPORTABLE and not dry_run:
                try:
                    rec["result"] = _import_one(run, it, st, payload)
                    rec["imported"] = True
                    rec["provenance"] = run.provenance
                except Exception as exc:  # noqa: BLE001 — one item must not stop the rest
                    db.session.rollback()
                    rec["error"] = "%s: %s" % (type(exc).__name__, exc)
            results.append(rec)
        if not dry_run:
            run.ledger.save()
        if progress:
            progress(len(chosen), len(chosen), None)
        out = dict(_pack_info(meta, key), version=manifest.get("version"),
                   signed_by=key.get("fingerprint"), dry_run=dry_run, items=results,
                   imported=sum(1 for r in results if r.get("imported")),
                   errors=sum(1 for r in results if r.get("error")),
                   rejected=sum(1 for r in results if r["state"] == ST_REJECTED),
                   unknown=sum(1 for r in results if r["state"] == ST_UNKNOWN),
                   warnings=_warnings(results))
        # A full pass (no ticked subset: the CLI, the installer, the runner)
        # is recorded even when everything was already here, so "this pack was
        # imported" stays answerable (pending_shipped).
        if not dry_run and (out["imported"] or out["errors"] or not ids):
            log = pack_dir() / "imports"
            log.mkdir(parents=True, exist_ok=True)
            stamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
            (log / ("%s-%s.json" % (stamp, _slug(manifest.get("version"))))).write_text(
                json.dumps(dict(out, actor=actor, pack=Path(path).name, partial=bool(ids)),
                           indent=1, default=str),
                encoding="utf-8")
        return out
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------------------
# where packs come from: the release's own copy, or an operator's upload
# ---------------------------------------------------------------------------

SOURCE_SHIPPED = "shipped"
SOURCE_UPLOADED = "uploaded"
PACK_SOURCES = (SOURCE_SHIPPED, SOURCE_UPLOADED)
MAX_UPLOAD_BYTES = 200 * 1024 * 1024
KEEP_UPLOADS = 5


def _source_dir(source: str) -> Path:
    if source == SOURCE_SHIPPED:
        return shipped_dir()
    if source == SOURCE_UPLOADED:
        return upload_dir()
    raise PackError("unknown pack source %r" % source)


#: Pack SERIES share ``api-packs/``. Each is CUMULATIVE (a full snapshot), so
#: per lineage only the NEWEST pack is ever imported:
#:   release   ``satom-apipack-<x.y.z>`` schema /1 (2.13 and older): exported
#:             from the release host's library;
#:   api_pack  schema /2, lane ``api_pack``: a satom-harvester snapshot pinned
#:             to a SATOM release (3.0+). Same lineage as ``release``: the
#:             3.0 pack supersedes the 2.x ones;
#:   knowledge ``satom-apipack-kb-YYYYMMDD[.N]``: /1 kb packs and /2 packs of
#:             lane ``knowledge`` — the rolling satom-harvester snapshot.
SERIES_RELEASE = "release"
SERIES_API_PACK = LANE_API_PACK
SERIES_KNOWLEDGE = LANE_KNOWLEDGE
SERIES_TRANSPORT = LANE_TRANSPORT
SERIES_ORDER = (SERIES_RELEASE, SERIES_API_PACK, SERIES_KNOWLEDGE, SERIES_TRANSPORT)
#: Supersession and import order run per LINEAGE.
_LINEAGE = {SERIES_RELEASE: SERIES_API_PACK, SERIES_API_PACK: SERIES_API_PACK,
            SERIES_KNOWLEDGE: SERIES_KNOWLEDGE, SERIES_TRANSPORT: SERIES_TRANSPORT}
_LINEAGE_ORDER = (SERIES_API_PACK, SERIES_KNOWLEDGE, SERIES_TRANSPORT)
KNOWLEDGE_PREFIX = "kb-"
SERIES_LABELS = {SERIES_RELEASE: "release pack",
                 SERIES_API_PACK: "API pack (pinned to a SATOM release)",
                 SERIES_KNOWLEDGE: "knowledge pack (satom-harvester)",
                 SERIES_TRANSPORT: "harvester transport pack (not importable)"}


def _pack_version(name: str) -> str:
    return name[len("satom-apipack-"):-len(".tar.gz")]


_PEEK: dict = {}


def peek_manifest(path) -> dict:
    """The manifest of a pack file, NOT verified — for labelling and ordering
    only (lane, snapshot). Every decision to import verifies it again. ``{}``
    when the file cannot be read. Cached by (path, size, mtime)."""
    p = Path(path)
    try:
        st = p.stat()
    except OSError:
        return {}
    ck = (str(p), st.st_size, st.st_mtime)
    if ck in _PEEK:
        return _PEEK[ck]
    out: dict = {}
    try:
        with tarfile.open(p, "r:gz") as tf:
            for m in tf:
                parts = Path(m.name).parts
                if len(parts) == 2 and parts[1] == "manifest.json" and m.isfile() \
                        and m.size < 64 * 1024 * 1024:
                    data = json.loads(tf.extractfile(m).read().decode("utf-8"))
                    out = data if isinstance(data, dict) else {}
                    break
    except (OSError, ValueError, tarfile.TarError, EOFError):
        out = {}
    if len(_PEEK) > 256:
        _PEEK.clear()
    _PEEK[ck] = out
    return out


def pack_series(name: str, manifest: dict | None = None) -> str:
    """Series of a pack: its ``lane`` for schema /2; a legacy /1 pack is
    ``knowledge`` when it is a satom-harvester ``kb-...`` pack, else ``release``."""
    m = manifest or {}
    if m.get("schema") == SCHEMA_V2 and isinstance(m.get("lane"), str) and m.get("lane"):
        return m["lane"] if m["lane"] in SERIES_ORDER else SERIES_TRANSPORT
    return (SERIES_KNOWLEDGE if _pack_version(name).startswith(KNOWLEDGE_PREFIX)
            else SERIES_RELEASE)


def _pack_version_key(name: str):
    """Version order inside ONE series. ``kb-20261007`` < ``kb-20261007.1`` <
    ``kb-20261007.10`` < ``kb-20261008``; ``2.9.1`` < ``2.10.0``. Every part is
    a tagged tuple, so comparing a number with a word never raises."""
    return tuple((0, int(x), "") if x.isdigit() else (1, 0, x)
                 for x in re.split(r"[.-]", _pack_version(name)))


def _lineage(series: str) -> str:
    return _LINEAGE.get(series, SERIES_TRANSPORT)


def _shipped_order(name: str, series: str | None = None):
    """Import order of shipped packs: the api_pack lineage (release packs and
    /2 api_packs) before the knowledge lineage, each by version. The import
    replaces only what a lower lane or an older pack of the same lane wrote,
    so the order decides who arrives first, not who wins."""
    series = series or pack_series(name)
    return (_LINEAGE_ORDER.index(_lineage(series)), _pack_version_key(name))


def _snapshot_of(manifest: dict) -> dict:
    snap = manifest.get("snapshot") if isinstance(manifest.get("snapshot"), dict) else {}
    return {"run_id": snap.get("run_id") if isinstance(snap.get("run_id"), int) else None,
            "built_at": str(snap.get("built_at") or ""),
            "content_fingerprint": str(manifest.get("content_fingerprint") or "")}


def list_packs() -> list:
    """Every pack this node can import from, newest first within each source.

    ``api-packs/`` keeps every release's pack, and a checkout gives them all
    the same mtime, so shipped packs are ordered by lineage then VERSION;
    uploads by when they arrived. A shipped pack that a newer one of its
    lineage replaces is flagged ``superseded``. Lane, schema and snapshot come
    from the (unverified) manifest and are labels only."""
    out = []
    done = _imported_names()
    for source in PACK_SOURCES:
        d = _source_dir(source)
        if not d.is_dir():
            continue
        found = [p for p in d.glob("satom-apipack-*.tar.gz")
                 if p.is_file() and PACK_NAME_RE.match(p.name)]
        man = {p.name: peek_manifest(p) for p in found}
        series_of = {p.name: pack_series(p.name, man[p.name]) for p in found}
        if source == SOURCE_SHIPPED:
            ranked = sorted(found, key=lambda p: _pack_version_key(p.name), reverse=True)
            ranked.sort(key=lambda p: _LINEAGE_ORDER.index(_lineage(series_of[p.name])))
        else:
            ranked = sorted(found, key=lambda p: p.stat().st_mtime, reverse=True)
        seen = set()
        for p in ranked:
            st = p.stat()
            m = man[p.name]
            series = series_of[p.name]
            lane = series if series in LANES or series == SERIES_TRANSPORT \
                else _legacy_lane(_pack_version(p.name))
            out.append({"source": source, "name": p.name, "size": st.st_size,
                        "version": _pack_version(p.name), "series": series,
                        "label": SERIES_LABELS.get(series, series),
                        "schema": m.get("schema") or "", "lane": lane,
                        "provenance": "%s%s:%s" % (PROV_PREFIX, lane, p.name[:-len(".tar.gz")]),
                        "pinned_to": str(m.get("pinned_to") or ""),
                        "min_satom": str(m.get("min_satom") or ""),
                        "snapshot": _snapshot_of(m),
                        "imported": p.name in done,
                        "superseded": source == SOURCE_SHIPPED and _lineage(series) in seen,
                        "mtime": datetime.utcfromtimestamp(int(st.st_mtime)).isoformat() + "Z"})
            seen.add(_lineage(series))
    return out


def resolve_pack(source: str, name: str) -> Path:
    """The file behind a (source, name) pair the page or the CLI was given.

    The name is matched against the pack pattern BEFORE it is joined to a
    directory, so ``../`` or an absolute path can never reach the filesystem.
    """
    if not PACK_NAME_RE.match(name or ""):
        raise PackError("%r is not an API pack name (satom-apipack-<version>.tar.gz)" % name)
    p = _source_dir(source) / name
    if not p.is_file():
        raise PackError("no %s pack named %s on this node" % (source, name))
    return p


def save_upload(stream, filename: str) -> dict:
    """Stage an uploaded pack. Staging verifies nothing: inspect and import do,
    every time, against the trust store as it is then."""
    name = os.path.basename(filename or "")
    if not PACK_NAME_RE.match(name):
        raise PackError("%r is not an API pack name (satom-apipack-<version>.tar.gz)" % name)
    d = upload_dir()
    part = d / (".%s.part" % name)
    size = 0
    try:
        with open(part, "wb") as fh:
            while True:
                chunk = stream.read(1 << 20)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_UPLOAD_BYTES:
                    raise PackError("larger than %d MB — that is not an API pack"
                                    % (MAX_UPLOAD_BYTES // 1048576))
                fh.write(chunk)
        os.replace(part, d / name)
    finally:
        part.unlink(missing_ok=True)
    kept = sorted((p for p in d.glob("satom-apipack-*.tar.gz") if p.name != name),
                  key=lambda p: p.stat().st_mtime, reverse=True)
    for old in kept[KEEP_UPLOADS - 1:]:
        old.unlink(missing_ok=True)
    return {"name": name, "size": size}


def delete_upload(name: str) -> None:
    resolve_pack(SOURCE_UPLOADED, name).unlink()


def _import_logs():
    d = pack_dir() / "imports"
    if not d.is_dir():
        return
    for f in sorted(d.glob("*.json"), reverse=True):
        try:
            rec = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(rec, dict):
            yield f, rec


def import_history(limit: int = 10) -> list:
    """The import log, newest first: what was imported, from which pack (lane
    and provenance), by whom."""
    out = []
    for f, rec in _import_logs():
        if len(out) >= limit:
            break
        stamp = f.name.split("-", 1)[0]
        try:
            at = datetime.strptime(stamp, "%Y%m%dT%H%M%SZ").isoformat() + "Z"
        except ValueError:
            at = stamp
        ver = str(rec.get("version") or "")
        lane = rec.get("lane") or _legacy_lane(ver)
        out.append({"at": at, "version": rec.get("version"), "pack": rec.get("pack"),
                    "actor": rec.get("actor") or "", "imported": rec.get("imported", 0),
                    "errors": rec.get("errors", 0), "lane": lane,
                    "schema": rec.get("schema") or SCHEMA_V1,
                    "provenance": rec.get("provenance")
                    or "%s%s:satom-apipack-%s" % (PROV_PREFIX, lane, ver),
                    "warnings": len(rec.get("warnings") or [])})
    return out


def _full_imports() -> list:
    """Logged full passes with no failed item (newest first)."""
    return [rec for _f, rec in _import_logs()
            if not rec.get("errors") and not rec.get("partial") and rec.get("pack")]


def _imported_names() -> set:
    """Packs this node has fully imported: a logged full pass with no failed
    item. A run that only took ticked items, or where an item failed, leaves
    the pack pending so the next update (or ``import shipped``) retries it."""
    return {rec["pack"] for rec in _full_imports()}


def _covered_by(pack: dict, imported: list) -> str:
    """The name of an imported pack whose snapshot already holds ``pack``'s
    content — the same content fingerprint, or a NEWER harvester run of any
    lane (both lanes are full snapshots of the same harvester) — else ``""``.
    Importing a covered pack would only bring older content back."""
    snap = pack.get("snapshot") or {}
    fp, run = snap.get("content_fingerprint"), snap.get("run_id")
    for rec in imported:
        other = _snapshot_of(rec)
        if fp and other["content_fingerprint"] == fp:
            return rec["pack"]
        if isinstance(run, int) and isinstance(other["run_id"], int) and other["run_id"] >= run:
            return rec["pack"]
    return ""


def pending_shipped(packs: list | None = None) -> list:
    """Shipped packs this node has not imported yet, in import order.

    Per lineage only the newest shipped pack counts (each one is cumulative):
    the api_pack of the running release (or the release pack of a 2.x tree)
    and the newest knowledge pack. A pack is NOT pending when an imported pack
    of either lane already carries its snapshot (same content fingerprint or a
    newer harvester run): an api_pack older than the knowledge pack the node
    fetched is not a regression to repair. The harvester transport lane is
    never pending. An update brings packs into ``api-packs/`` and the runner
    imports them on the primary; the page uses this to say so when that did
    not happen. ``[]`` when there is nothing to do."""
    shipped = [p for p in (packs if packs is not None else list_packs())
               if p["source"] == SOURCE_SHIPPED and not p.get("superseded")
               and p.get("series") != SERIES_TRANSPORT]
    if not shipped:
        return []
    full = _full_imports()
    done = {rec["pack"] for rec in full}
    out = [p for p in shipped if p["name"] not in done and not _covered_by(p, full)]
    return sorted(out, key=lambda p: _shipped_order(p["name"], p.get("series")))


__all__ = ["SCHEMA", "SCHEMA_V1", "SCHEMA_V2", "SECTIONS", "IMPORT_SECTIONS", "LANES",
           "ORIGIN_PREFIX", "PackError", "ItemInvalid", "rebuild_document", "export_pack",
           "inspect_pack", "import_pack", "list_packs", "resolve_pack", "save_upload",
           "delete_upload", "import_history", "pending_shipped", "pack_series",
           "peek_manifest", "SERIES_LABELS", "lane_keys", "trust_summary", "outranks",
           "evidence_provenance"]
