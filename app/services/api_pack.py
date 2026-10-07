"""API library packs — move what one SATOM knows about vendor APIs to another.

Design contract: ``docs/api-library.md`` §11. Why this exists: an installation
with no internet and no appliance of a given build has no way to learn what
that build serves. Sweeps need the box, the vendor collections need Galaxy,
and the release notes and field catalog need docs.fortinet.com and our LAN
Firecrawl. A pack carries all three kinds of knowledge as one signed tarball,
so an offline node imports it the same way it applies an update package.

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
   is never overwritten. Import only ever adds.
4. **Signed or refused.** Same verifier and same root-owned trust store as
   update packages (``deploy/update_package.py``); an unsigned pack and a
   badly signed one are the same refusal.
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

SCHEMA = "satom.api-pack/1"
PRODUCT = "satom"

SECTION_LIBRARY = "library"
SECTION_DOCS = "docs"
SECTION_CLI = "cli-coverage"
SECTIONS = (SECTION_LIBRARY, SECTION_DOCS, SECTION_CLI)

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
# verify + inspect
# ---------------------------------------------------------------------------

def _open(path, tmp: Path, trust_dir) -> tuple:
    path = Path(path)
    if not PACK_NAME_RE.match(path.name):
        raise PackError("%r is not an API pack name (satom-apipack-<version>.tar.gz)" % path.name)
    try:
        pkg = up.extract_package(path, tmp)
        problem = up.trust_store_problem(trust_dir)
        if problem:
            raise PackError("trust store is not safe to use: %s" % problem)
        key = up.verify_signature(pkg, trust_dir)
        manifest = up.read_manifest(pkg)
    except up.PackageError as exc:
        raise PackError(str(exc))
    if manifest.get("schema") != SCHEMA:
        raise PackError("unsupported pack schema %r (this node speaks %s)"
                        % (manifest.get("schema"), SCHEMA))
    if manifest.get("product") != PRODUCT:
        raise PackError("pack is for product %r, not %s" % (manifest.get("product"), PRODUCT))
    problems = up.verify_contents(pkg, manifest)
    if problems:
        raise PackError("pack contents do not match the signed manifest: %s"
                        % "; ".join(problems[:5]))
    for it in manifest.get("items") or []:
        if it.get("file") not in (manifest.get("files") or {}):
            raise PackError("item %s names a file the manifest does not sign" % it.get("id"))
    return pkg, manifest, key


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
    if doc["source"] != lib.SOURCE_VENDOR:
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


def _release_pairs() -> set:
    from . import release_notes as rn
    corpus = rn.load_db(root=_release_root())
    if corpus is None:
        return set()
    return ({(i.product, i.version) for i in corpus.issues}
            | {(s.product, s.version) for s in corpus.sections})


def _item_state(pkg: Path, it: dict, cache: dict) -> dict:
    f = pkg / it["file"]
    sec, kind = it["section"], it.get("kind")
    if sec == SECTION_LIBRARY:
        return {"state": _library_state(_read_gz_json(f))}
    if sec == SECTION_DOCS and kind == "release-notes":
        if "pairs" not in cache:
            cache["pairs"] = _release_pairs()
        new = [v for v in it.get("versions") or [] if (it["product"], v) not in cache["pairs"]]
        return {"state": ST_NEW if new else ST_PRESENT, "new_versions": new}
    if sec == SECTION_DOCS and kind == "field-schemas":
        d = _schema_root() / it["product"] / it["line"]
        new = [o for o in it.get("objects") or [] if not (d / ("%s.json" % o)).exists()]
        return {"state": ST_NEW if new else ST_PRESENT, "new_objects": new}
    if sec == SECTION_DOCS and kind == "field-overlay":
        return {"state": ST_PRESENT if _overlay_path().exists() else ST_NEW}
    if sec == SECTION_CLI:
        dest = pack_dir() / "cli-coverage" / it["product"] / ("%s.json" % _slug(it["version"]))
        if dest.exists() and json.loads(dest.read_text()) == _read_gz_json(f):
            return {"state": ST_PRESENT}
        return {"state": ST_NEW}
    return {"state": ST_PRESENT, "note": "unknown item kind; ignored"}


def inspect_pack(path, trust_dir=None) -> dict:
    """Verify a pack and say, per item, what importing it would do."""
    tmp = Path(tempfile.mkdtemp(prefix="satom-apipack-"))
    try:
        pkg, manifest, key = _open(path, tmp, trust_dir or TRUST_DIR)
        cache: dict = {}
        items = [dict(it, **_item_state(pkg, it, cache)) for it in manifest.get("items") or []]
        return {"version": manifest.get("version"), "built_at": manifest.get("built_at"),
                "signed_by": {"fingerprint": key.get("fingerprint"),
                              "comment": key.get("comment", "")},
                "notes": manifest.get("notes", ""), "items": items}
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


def _import_release_notes(pkg: Path, it: dict, new_versions) -> dict:
    from . import release_notes as rn
    data = _read_gz_json(pkg / it["file"])
    want = set(new_versions)
    root = _release_root()
    corpus = rn.load_db(root=root) or rn.ReleaseNotesDB(generated_at=data.get("generated_at") or "")
    issues = [rn.ReleaseIssue(**{k: v for k, v in d.items() if k in rn.ReleaseIssue.__annotations__})
              for d in data.get("issues") or [] if d.get("version") in want]
    sects = [rn.ReleaseSection(**{k: v for k, v in d.items() if k in rn.ReleaseSection.__annotations__})
             for d in data.get("sections") or [] if d.get("version") in want]
    corpus.issues += issues
    corpus.sections += sects
    corpus.versions = sorted(set(corpus.versions) | want, key=rn.version_key)
    rn.save_db(corpus, root=root)
    return {"versions": sorted(want, key=rn.version_key), "issues": len(issues),
            "sections": len(sects)}


def _import_field_schemas(pkg: Path, it: dict, new_objects) -> dict:
    objs = _read_gz_json(pkg / it["file"])
    d = _schema_root() / it["product"] / it["line"]
    d.mkdir(parents=True, exist_ok=True)
    written = []
    for o in new_objects:
        p = d / ("%s.json" % _slug(o))
        if p.exists() or o not in objs:
            continue
        p.write_text(json.dumps(objs[o], indent=2, ensure_ascii=False), encoding="utf-8")
        written.append(o)
    return {"objects": written}


def _import_one(pkg: Path, it: dict, st: dict) -> dict:
    sec, kind = it["section"], it.get("kind")
    if sec == SECTION_LIBRARY:
        res = lib.ingest(_read_gz_json(pkg / it["file"]))
        return {"evidence_id": res["evidence_id"], "created": res["created"]}
    if kind == "release-notes":
        return _import_release_notes(pkg, it, st.get("new_versions") or [])
    if kind == "field-schemas":
        return _import_field_schemas(pkg, it, st.get("new_objects") or [])
    if kind == "field-overlay":
        p = _overlay_path()
        if not p.exists():
            p.write_text(json.dumps(_read_gz_json(pkg / it["file"]), indent=2,
                                    ensure_ascii=False), encoding="utf-8")
            from . import fortiweb_field_schema
            fortiweb_field_schema._overlay.cache_clear()
        return {"written": str(p.name)}
    if sec == SECTION_CLI:
        dest = pack_dir() / "cli-coverage" / it["product"] / ("%s.json" % _slug(it["version"]))
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(json.dumps(_read_gz_json(pkg / it["file"]), indent=1,
                                   ensure_ascii=False), encoding="utf-8")
        return {"written": str(dest.relative_to(pack_dir()))}
    return {"ignored": True}


def import_pack(path, *, trust_dir=None, products=None, sections=None, ids=None,
                dry_run: bool = False, actor: str = "", progress=None) -> dict:
    """Verify, then import the selected items that are ``new``.

    ``present`` and ``local`` items are reported and never touched (rule 3).
    Every run that imports something is logged under ``apipacks/imports/``.
    ``progress(done, total, item_id)`` is called before each selected item, and
    once more with ``item_id=None`` when the last one is finished.
    """
    products, sections, ids = set(products or ()), set(sections or ()), set(ids or ())
    tmp = Path(tempfile.mkdtemp(prefix="satom-apipack-"))
    try:
        pkg, manifest, key = _open(path, tmp, trust_dir or TRUST_DIR)
        known = {it["id"] for it in manifest.get("items") or []}
        if ids - known:
            raise PackError("not in this pack: %s" % ", ".join(sorted(ids - known)))
        cache: dict = {}
        results = []
        chosen = [it for it in manifest.get("items") or []
                  if _selected(it, products, sections, ids)]
        for n, it in enumerate(chosen):
            if progress:
                progress(n, len(chosen), it["id"])
            st = _item_state(pkg, it, cache)
            rec = {"id": it["id"], "section": it["section"], "product": it.get("product"),
                   "state": st["state"]}
            if st["state"] == ST_NEW and not dry_run:
                try:
                    rec["result"] = _import_one(pkg, it, st)
                    rec["imported"] = True
                    cache.pop("pairs", None)
                except Exception as exc:  # noqa: BLE001 — one item must not stop the rest
                    db.session.rollback()
                    rec["error"] = "%s: %s" % (type(exc).__name__, exc)
            results.append(rec)
        if progress:
            progress(len(chosen), len(chosen), None)
        out = {"version": manifest.get("version"), "signed_by": key.get("fingerprint"),
               "dry_run": dry_run, "items": results,
               "imported": sum(1 for r in results if r.get("imported")),
               "errors": sum(1 for r in results if r.get("error"))}
        # A full pass (no ticked subset: the CLI, the installer, the runner)
        # is recorded even when everything was already here, so "this pack was
        # imported" stays answerable (pending_shipped).
        if not dry_run and (out["imported"] or out["errors"] or not ids):
            log = pack_dir() / "imports"
            log.mkdir(parents=True, exist_ok=True)
            stamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
            (log / ("%s-%s.json" % (stamp, _slug(manifest.get("version"))))).write_text(
                json.dumps(dict(out, actor=actor, pack=Path(path).name), indent=1),
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


def _pack_version_key(name: str):
    ver = name[len("satom-apipack-"):-len(".tar.gz")]
    return tuple((0, int(x), "") if x.isdigit() else (1, 0, x)
                 for x in re.split(r"[.-]", ver))


def list_packs() -> list:
    """Every pack this node can import from, newest first within each source.

    ``api-packs/`` keeps every release's pack, and a checkout gives them all
    the same mtime, so shipped packs are ordered by VERSION; uploads by when
    they arrived."""
    out = []
    for source in PACK_SOURCES:
        d = _source_dir(source)
        if not d.is_dir():
            continue
        found = [p for p in d.glob("satom-apipack-*.tar.gz")
                 if p.is_file() and PACK_NAME_RE.match(p.name)]
        order = ((lambda p: _pack_version_key(p.name)) if source == SOURCE_SHIPPED
                 else (lambda p: p.stat().st_mtime))
        for p in sorted(found, key=order, reverse=True):
            st = p.stat()
            out.append({"source": source, "name": p.name, "size": st.st_size,
                        "version": p.name[len("satom-apipack-"):-len(".tar.gz")],
                        "mtime": datetime.utcfromtimestamp(int(st.st_mtime)).isoformat() + "Z"})
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


def import_history(limit: int = 10) -> list:
    """The import log, newest first: what was imported, from which pack, by whom."""
    d = pack_dir() / "imports"
    if not d.is_dir():
        return []
    out = []
    for f in sorted(d.glob("*.json"), reverse=True)[:limit]:
        try:
            rec = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        stamp = f.name.split("-", 1)[0]
        try:
            at = datetime.strptime(stamp, "%Y%m%dT%H%M%SZ").isoformat() + "Z"
        except ValueError:
            at = stamp
        out.append({"at": at, "version": rec.get("version"), "pack": rec.get("pack"),
                    "actor": rec.get("actor") or "", "imported": rec.get("imported", 0),
                    "errors": rec.get("errors", 0)})
    return out


def pending_shipped(packs: list | None = None) -> dict | None:
    """The newest shipped pack if this node has never imported it, else None.

    An update brings a new pack into ``api-packs/`` and the runner imports it
    on the primary; this is what the page uses to say so when that did not
    happen (a standby promoted later, an update applied by an older runner, an
    import that failed)."""
    shipped = [p for p in (packs if packs is not None else list_packs())
               if p["source"] == SOURCE_SHIPPED]
    if not shipped:
        return None
    newest = shipped[0]
    d = pack_dir() / "imports"
    if d.is_dir():
        for f in d.glob("*.json"):
            try:
                if json.loads(f.read_text(encoding="utf-8")).get("pack") == newest["name"]:
                    return None
            except (OSError, ValueError):
                continue
    return newest


__all__ = ["SCHEMA", "SECTIONS", "ORIGIN_PREFIX", "PackError", "rebuild_document",
           "export_pack", "inspect_pack", "import_pack", "list_packs", "resolve_pack",
           "save_upload", "delete_upload", "import_history", "pending_shipped"]
