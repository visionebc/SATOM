"""Deploy-to-deploy clone: copy one SATOM installation's data into another.

A clone is not a restore. A system bundle (:mod:`system_backup`) puts a deploy
back the way it was: it carries the source's ciphertext and leaves the key to
the operator. A clone moves data between two installations that each keep
their own FERNET_KEY, their own identity and their own HA pair:

* rows travel as JSON, one file per table, checked column for column against
  the target's schema before anything is written;
* every Fernet token is re-encrypted in transit -- under a one-time transfer
  key on export, under the target's own key on import. No node's key ever
  leaves the node. The transfer key travels sealed with a passphrase that the
  export prints once and stores nowhere;
* node identity (HA role, node certificate, backup server, signature store,
  recovery escrow) belongs to the target and stays the target's;
* the imported deploy starts QUARANTINED: every schedule, alert e-mail, NetBox
  push and hook that was enabled on the source is switched off until an
  operator releases it. Two installations polling and writing the same
  appliances is what a clone otherwise produces, silently.

Scope ``full`` replaces the target's data. Partial clones reuse this format.
"""
from __future__ import annotations

import base64
import gzip
import hashlib
import json
import os
import re
import shutil
import socket
import tarfile
from datetime import date, datetime
from decimal import Decimal
from pathlib import Path

FORMAT = "satom-clone/1"
SCOPE_FULL = "full"
PASSPHRASE_ENV = "SATOM_CLONE_PASSPHRASE"

QUARANTINE_KEY = "deployclone.quarantine"
LAST_IMPORT_KEY = "deployclone.last_import"

#: Tables that describe the node, not the estate: leases held by this node's
#: processes, and the signature store, which every node fetches for itself
#: (its rows only make sense next to that node's data/signatures/).
NODE_LOCAL_TABLES = frozenset({
    "resource_locks",
    "signature_entries", "signature_changes", "signature_snapshots",
    "knowledge_signature_meta",
})
#: Rows that point at files under data/firmware/. They travel with the files
#: or not at all: rows without their images are a catalogue of missing files.
FIRMWARE_TABLES = frozenset({"firmware_images"})

#: app_settings keys that are the node's own. Never exported, and the target's
#: values survive the import untouched.
NODE_LOCAL_SETTING_PREFIXES = (
    "ha.",                      # HA role, peer, reconcile state
    "security.",                # node certificate, node identity key, pg TLS
    "backup_server.",           # where THIS node pushes its bundles
    "signatures.",              # pairs with the node-local signature tables
    "recovery.escrow.",         # fingerprints of THIS node's key and CA
    "deployclone.",             # this module's own state
    "alerts.state", "alerts.last_email",
    "knowledge.fetch_last", "sot.log_archive_last",
    "apilib.schema_watch.", "metrics.peer_dual_write",
)

#: Settings switched off by the quarantine, with the value that means "off".
QUARANTINE_FLAGS = (
    ("alerts.enabled", "0"),
    ("email.enabled", "0"),
    ("integrations.netbox.enabled", "0"),
)

_TOKEN_RX = re.compile(r"gAAAAA[A-Za-z0-9_\-]{60,}={0,2}")
_NAME_RX = re.compile(r"^satom-clone-[A-Za-z0-9._-]+\.tar\.gz$")

#: A passphrase handed in (console, $SATOM_CLONE_PASSPHRASE) is refused below
#: this; the generated ones are six words.
MIN_PASSPHRASE_LEN = 16

#: Request kind the privileged runner executes for the console. The runner
#: holds its own copy of the action list (it never imports this package).
RUNNER_KIND = "clone"
RUNNER_ACTIONS = ("export", "import")


class CloneError(Exception):
    """A clone that must not proceed. Raised before anything is written."""


# ---------------------------------------------------------------------------
# places
# ---------------------------------------------------------------------------

def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _data_root() -> Path:
    return Path(os.environ.get("SATOM_CLONE_DATA_DIR")
                or (_repo_root() / "data"))


def exports_dir() -> Path:
    from . import system_backup as sb
    d = _data_root() / "clone-exports"
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    sb._keep_private_dir(d)
    return d


def imports_dir() -> Path:
    """Bundles waiting to be imported. The CLI copies a bundle here before it
    hands it to the app; the console uploads straight into it."""
    from . import system_backup as sb
    d = _data_root() / "clone-imports"
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    sb._keep_private_dir(d)
    return d


def _file_sets(with_firmware: bool) -> list:
    """(name, directory, subdirectories or None for all).

    Queues are left behind on purpose: data/scripts/queue and
    data/integrations/queue are requests the SOURCE's runners were asked to
    execute. Copied, the target's runner would execute them a second time.
    """
    from . import integration_hooks as ih
    from . import script_library as sl
    from . import system_backup as sb
    from . import waf_artifacts as wa
    sets = [
        ("vault", sb.vault_dir(), None),
        ("reports", sb.reports_dir(), None),
        ("sot", sb.sot_dir(), None),
        ("scripts", sl.ROOT, ("library", "schedules")),
        ("integrations", ih.HOOKS_DIR.parent, ("hooks",)),
        ("artifacts", wa.store_dir(), ("objects",)),
        ("branding", _data_root() / "branding", None),
    ]
    if with_firmware:
        sets.append(("firmware", _data_root() / "firmware", None))
    return sets


def is_node_local_setting(key: str) -> bool:
    return any(key.startswith(p) for p in NODE_LOCAL_SETTING_PREFIXES)


def _skipped_tables(with_firmware: bool) -> frozenset:
    return NODE_LOCAL_TABLES | (frozenset() if with_firmware else FIRMWARE_TABLES)


# ---------------------------------------------------------------------------
# keys
# ---------------------------------------------------------------------------

def _node_fernet():
    from cryptography.fernet import Fernet
    raw = os.environ.get("FERNET_KEY") or ""
    if not raw:
        raise CloneError("FERNET_KEY is not set on this node")
    return Fernet(raw.encode())


class _Rekeyer:
    """Re-encrypt every Fernet token found in a value from one key to another.

    Tokens are found by shape and confirmed by their HMAC, so only real tokens
    under ``old`` are touched -- also the ones embedded in JSON text (certmgr
    settings, provider blobs), which a column list would miss. A token-shaped
    string ``old`` does not open is left as it is and counted: it was already
    unreadable on the source.
    """

    def __init__(self, old, new):
        self.old, self.new = old, new
        self.rekeyed = 0
        self.foreign = 0
        self.vaulted = 0
        from .secret_backend import VAULT_SENTINEL
        self._sentinel = VAULT_SENTINEL.encode()

    def _sub(self, m):
        from cryptography.fernet import InvalidToken
        tok = m.group(0)
        try:
            plain = self.old.decrypt(tok.encode())
        except (InvalidToken, ValueError):
            self.foreign += 1
            return tok
        self.rekeyed += 1
        if plain == self._sentinel:
            self.vaulted += 1
        return self.new.encrypt(plain).decode()

    def value(self, v):
        if isinstance(v, str):
            return _TOKEN_RX.sub(self._sub, v) if "gAAAAA" in v else v
        if isinstance(v, list):
            return [self.value(x) for x in v]
        if isinstance(v, dict):
            return {k: self.value(x) for k, x in v.items()}
        return v

    def counts(self) -> dict:
        return {"rekeyed": self.rekeyed, "foreign": self.foreign,
                "vaulted": self.vaulted}


def _seal_key(transfer_key: bytes, passphrase: str, source: dict) -> dict:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from . import recovery_seal as rs
    salt, nonce = os.urandom(rs._SALT_LEN), os.urandom(rs._NONCE_LEN)
    header = {"v": 1, "kdf": {"name": "scrypt", "n": rs._SCRYPT_N,
                              "r": rs._SCRYPT_R, "p": rs._SCRYPT_P,
                              "salt": base64.b64encode(salt).decode()},
              "nonce": base64.b64encode(nonce).decode(), "source": source}
    key = rs._derive(passphrase, salt, rs._SCRYPT_N, rs._SCRYPT_R, rs._SCRYPT_P)
    ct = AESGCM(key).encrypt(nonce, transfer_key, _aad(header))
    return dict(header, ct=base64.b64encode(ct).decode())


def _aad(header: dict) -> bytes:
    return json.dumps({k: header[k] for k in ("v", "kdf", "nonce", "source")},
                      sort_keys=True).encode()


def _unseal_key(doc: dict, passphrase: str) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from . import recovery_seal as rs
    try:
        kdf = doc["kdf"]
        salt = base64.b64decode(kdf["salt"])
        nonce = base64.b64decode(doc["nonce"])
        ct = base64.b64decode(doc["ct"])
        header = {k: doc[k] for k in ("v", "kdf", "nonce", "source")}
    except (KeyError, TypeError, ValueError) as exc:
        raise CloneError("transfer key envelope is malformed") from exc
    key = rs._derive(passphrase or "", salt, int(kdf["n"]), int(kdf["r"]),
                     int(kdf["p"]))
    try:
        return AESGCM(key).decrypt(nonce, ct, _aad(header))
    except Exception as exc:  # noqa: BLE001 - InvalidTag
        # One message for both, as in recovery_seal: telling them apart helps
        # only someone who is guessing.
        raise CloneError("could not open the transfer key: wrong passphrase, "
                         "or the bundle has been altered") from exc


# ---------------------------------------------------------------------------
# rows
# ---------------------------------------------------------------------------

def _encode(v):
    if isinstance(v, (datetime, date)):
        return v.isoformat()
    if isinstance(v, (bytes, bytearray, memoryview)):
        return base64.b64encode(bytes(v)).decode()
    if isinstance(v, Decimal):
        return str(v)
    return v


def _decode(column, v):
    import sqlalchemy as sa
    if v is None:
        return None
    t = column.type
    if isinstance(t, sa.DateTime):
        return datetime.fromisoformat(v)
    if isinstance(t, sa.Date):
        return date.fromisoformat(v)
    if isinstance(t, sa.LargeBinary):
        return base64.b64decode(v)
    return v


def _rekey_row(table, row: dict, rk: _Rekeyer) -> dict:
    import sqlalchemy as sa
    out = {}
    for c in table.columns:
        v = row.get(c.name)
        if v is not None and not isinstance(c.type, sa.LargeBinary):
            v = rk.value(v)
        out[c.name] = v
    return out


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _alembic_revision():
    from sqlalchemy import text
    from ..extensions import db
    try:
        return db.session.execute(
            text("SELECT version_num FROM alembic_version")).scalar()
    except Exception:  # noqa: BLE001 - no alembic table (tests, fresh SQLite)
        db.session.rollback()
        return None


def _version() -> str:
    try:
        return (_repo_root() / "VERSION").read_text().strip()
    except OSError:
        return ""


def _is_replica() -> bool:
    from . import alerts
    return alerts._is_read_only_replica()


# ---------------------------------------------------------------------------
# export
# ---------------------------------------------------------------------------

def export_clone(*, with_firmware: bool = False, by: str = "system",
                 out_dir: Path | None = None, passphrase: str | None = None) -> dict:
    """Write a clone bundle of this whole deploy. Read-only on the node.

    Returns the bundle's name, path, size and the passphrase -- the only time
    the passphrase exists anywhere outside the operator's hands. The console
    passes one in: it has already shown it to the operator, because the export
    itself runs in the privileged runner and its result is a status file that
    must never hold it.
    """
    from cryptography.fernet import Fernet
    from ..extensions import db
    from . import recovery, system_backup as sb

    if passphrase is not None and len(passphrase) < MIN_PASSPHRASE_LEN:
        raise CloneError("the passphrase must be at least %d characters"
                         % MIN_PASSPHRASE_LEN)
    source_key = _node_fernet()
    transfer = Fernet.generate_key()
    rk = _Rekeyer(source_key, Fernet(transfer))
    passphrase = passphrase or new_passphrase()
    out_dir = Path(out_dir) if out_dir else exports_dir()
    ts = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    node = re.sub(r"[^A-Za-z0-9.-]", "-", socket.gethostname())[:60] or "node"
    name = "satom-clone-%s-%s.tar.gz" % (node, ts)
    stage = out_dir / ("_stage-" + ts)
    (stage / "tables").mkdir(mode=0o700, parents=True)
    (stage / "files").mkdir(mode=0o700)
    skip = _skipped_tables(with_firmware)
    tables, files, rows_total = {}, {}, 0
    try:
        for t in db.metadata.sorted_tables:
            if t.name in skip:
                continue
            path = stage / "tables" / (t.name + ".jsonl.gz")
            q = t.select()
            if t.primary_key.columns:
                q = q.order_by(*t.primary_key.columns)
            n = 0
            conn = db.session.connection().execution_options(yield_per=2000)
            with gzip.open(path, "wt", encoding="utf-8") as fh:
                for row in conn.execute(q).mappings():
                    if t.name == "app_settings" and is_node_local_setting(row["key"]):
                        continue
                    rec = _rekey_row(t, dict(row), rk)
                    fh.write(json.dumps({k: _encode(v) for k, v in rec.items()},
                                        separators=(",", ":")) + "\n")
                    n += 1
            tables[t.name] = {"rows": n, "columns": [c.name for c in t.columns],
                              "sha256": _sha256(path)}
            rows_total += n
        db.session.rollback()          # end the read transaction

        for fname, d, subdirs in _file_sets(with_firmware):
            path = stage / "files" / (fname + ".tar")
            count, size = 0, 0
            with tarfile.open(path, "w") as tar:
                roots = [d / s for s in subdirs] if subdirs else [d]
                for root in roots:
                    if not root.is_dir():
                        continue
                    for p in sorted(root.rglob("*")):
                        if p.is_symlink() or not (p.is_file() or p.is_dir()):
                            continue
                        tar.add(str(p), arcname=str(p.relative_to(d)),
                                recursive=False)
                        if p.is_file():
                            count += 1
                            size += p.stat().st_size
            files[fname] = {"files": count, "bytes": size,
                            "subdirs": list(subdirs) if subdirs else None,
                            "sha256": _sha256(path)}

        source = {"node": node, "version": _version(),
                  "alembic": _alembic_revision(),
                  "fernet_fingerprint": recovery.fernet_fingerprint()}
        (stage / "transfer-key.json").write_text(
            json.dumps(_seal_key(transfer, passphrase, source), indent=2))
        manifest = {"format": FORMAT, "scope": SCOPE_FULL,
                    "created": datetime.utcnow().isoformat(timespec="seconds") + "Z",
                    "by": by, "source": source, "with_firmware": with_firmware,
                    "tables": tables, "files": files, "rekey": rk.counts(),
                    "node_local_tables": sorted(skip),
                    "node_local_setting_prefixes": list(NODE_LOCAL_SETTING_PREFIXES)}
        (stage / "manifest.json").write_text(json.dumps(manifest, indent=2))

        bundle = out_dir / name
        with sb._open_private(bundle) as fh, \
                tarfile.open(fileobj=fh, mode="w:gz") as tar:
            for member in ("manifest.json", "transfer-key.json", "tables", "files"):
                tar.add(str(stage / member), arcname=member)
    finally:
        shutil.rmtree(stage, ignore_errors=True)

    _audit("deploy_clone.export", name,
           {"tables": len(tables), "rows": rows_total, "rekey": rk.counts(),
            "with_firmware": with_firmware})
    return {"ok": True, "name": name, "path": str(out_dir / name),
            "size": (out_dir / name).stat().st_size, "passphrase": passphrase,
            "tables": len(tables), "rows": rows_total,
            "files": {k: v["files"] for k, v in files.items()},
            "rekey": rk.counts()}


# ---------------------------------------------------------------------------
# import
# ---------------------------------------------------------------------------

def _safe_member(member: tarfile.TarInfo, dest: Path) -> bool:
    from . import system_backup as sb
    return sb._safe_member(member, dest)


def _extract(tar: tarfile.TarFile, dest: Path) -> None:
    members = [m for m in tar.getmembers() if _safe_member(m, dest)]
    if hasattr(tarfile, "data_filter"):
        tar.extractall(dest, members=members, filter="data")
    else:                                          # pragma: no cover
        tar.extractall(dest, members=members)


def _read_manifest(root: Path) -> dict:
    try:
        m = json.loads((root / "manifest.json").read_text())
    except (OSError, ValueError) as exc:
        raise CloneError("not a SATOM clone bundle (no readable manifest)") from exc
    if m.get("format") != FORMAT:
        raise CloneError("unsupported bundle format %r (this node reads %s)"
                         % (m.get("format"), FORMAT))
    return m


def check_bundle(root: Path, manifest: dict) -> list:
    """Every reason this bundle cannot be imported HERE. Empty = importable."""
    problems = compat_problems(manifest)
    for name, info in sorted((manifest.get("tables") or {}).items()):
        p = root / "tables" / (name + ".jsonl.gz")
        if not p.is_file() or _sha256(p) != info.get("sha256"):
            problems.append("table %s is missing or altered" % name)
    for name, info in sorted((manifest.get("files") or {}).items()):
        p = root / "files" / (name + ".tar")
        if not p.is_file() or _sha256(p) != info.get("sha256"):
            problems.append("file set %s is missing or altered" % name)
    return problems


def compat_problems(manifest: dict) -> list:
    """The reasons that need only the manifest: same deploy, schema revision,
    tables and columns. The console asks this before queueing an import, so an
    operator hears it in the page and not from a runner minutes later."""
    from ..extensions import db
    from . import recovery
    problems = []
    src = manifest.get("source") or {}
    if src.get("fernet_fingerprint") and \
            src["fernet_fingerprint"] == recovery.fernet_fingerprint():
        problems.append("this bundle was exported from this deploy (same "
                        "FERNET_KEY); to roll this deploy back use "
                        "'satom execute restore db'")
    if (src.get("alembic") or None) != (_alembic_revision() or None):
        problems.append("schema revision differs: bundle %s, this node %s -- "
                        "update both deploys to the same SATOM version first"
                        % (src.get("alembic") or "none",
                           _alembic_revision() or "none"))
    meta = db.metadata.tables
    skip = set(manifest.get("node_local_tables") or ())
    for name, info in sorted((manifest.get("tables") or {}).items()):
        t = meta.get(name)
        if t is None:
            problems.append("table %s is not in this node's schema" % name)
            continue
        if list(info.get("columns") or []) != [c.name for c in t.columns]:
            problems.append("table %s has different columns here" % name)
    for name in sorted(set(meta) - set(manifest.get("tables") or {}) - skip):
        problems.append("table %s exists here but not in the bundle" % name)
    return problems


def _rows(root: Path, table):
    with gzip.open(root / "tables" / (table.name + ".jsonl.gz"), "rt",
                   encoding="utf-8") as fh:
        for line in fh:
            rec = json.loads(line)
            yield {c.name: _decode(c, rec.get(c.name)) for c in table.columns}


def _null_json(t):
    """The column's own JSON type (JSONB variant included) with None -> NULL.

    A copy of the column's type, not a fresh ``sa.JSON``: on Postgres a jsonb
    column bound as plain json depends on a cast the server may refuse."""
    import copy
    t = copy.copy(t)
    t.none_as_null = True
    vm = getattr(t, "_variant_mapping", None)
    if vm:
        new = {}
        for name, v in vm.items():
            v = copy.copy(v)
            v.none_as_null = True
            new[name] = v
        t._variant_mapping = vm.__class__(new)
    return t


def _insert_table(table, rows, rk: _Rekeyer, batch: int = 1000) -> int:
    """Insert, deferring self-references: a row may name a parent that sorts
    after it, and the FK would refuse it mid-batch."""
    import sqlalchemy as sa
    from ..extensions import db
    selfcols = sorted({fk.parent.name for fk in table.foreign_keys
                       if fk.column.table is table})
    pk = [c.name for c in table.primary_key.columns]
    # A JSON column binds Python None as the JSON value null, not SQL NULL, so
    # a NULL read on the source would come back as 'null' and stop matching
    # IS NULL. Bind those columns with none_as_null.
    stmt = table.insert()
    json_cols = [c.name for c in table.columns if isinstance(c.type, sa.JSON)]
    if json_cols:
        # Renamed binds: a bindparam named like its own column is reserved
        # for SQLAlchemy's automatic VALUES parameters.
        stmt = stmt.values({c: sa.bindparam("_json_" + c,
                                            type_=_null_json(table.c[c].type))
                            for c in json_cols})
    deferred, buf, n = [], [], 0
    for row in rows:
        row = _rekey_row(table, row, rk)
        if selfcols and any(row.get(c) is not None for c in selfcols):
            deferred.append(({k: row[k] for k in pk},
                             {c: row[c] for c in selfcols}))
            row = dict(row, **{c: None for c in selfcols})
        for c in json_cols:
            row["_json_" + c] = row.pop(c)
        buf.append(row)
        if len(buf) >= batch:
            db.session.execute(stmt, buf)
            n += len(buf)
            buf = []
    if buf:
        db.session.execute(stmt, buf)
        n += len(buf)
    for key, vals in deferred:
        cond = [table.c[k] == v for k, v in key.items()]
        db.session.execute(table.update().where(*cond).values(**vals))
    return n


def _reset_sequences(tables) -> None:
    from sqlalchemy import text
    from ..extensions import db
    if db.engine.dialect.name != "postgresql":
        return
    for t in tables:
        cols = list(t.primary_key.columns)
        if len(cols) != 1 or not str(cols[0].type).upper().startswith(("INTEGER", "BIGINT")):
            continue
        seq = db.session.execute(text("SELECT pg_get_serial_sequence(:t, :c)"),
                                 {"t": '"%s"' % t.name, "c": cols[0].name}).scalar()
        if seq:
            db.session.execute(text(
                'SELECT setval(:s, COALESCE((SELECT max("%s") FROM "%s"), 1), '
                '(SELECT max("%s") FROM "%s") IS NOT NULL)'
                % (cols[0].name, t.name, cols[0].name, t.name)), {"s": seq})


def _quarantine_db(record: dict) -> None:
    """Switch off what would act on appliances or people. Same transaction as
    the rows, so no tick of the scheduler can ever see the clone un-held."""
    from ..extensions import db
    from ..models import AppSetting, ScheduledAction
    held = []
    for a in db.session.query(ScheduledAction).all():
        a.running_at = None
        if a.enabled:
            held.append(a.id)
            a.enabled = False
    record["actions"] = held
    flags = {}
    for key, off in QUARANTINE_FLAGS:
        row = db.session.get(AppSetting, key)
        if row is not None and row.value != off:
            flags[key] = row.value
            row.value = off
    record["flags"] = flags


def _quarantine_files(record: dict) -> None:
    from . import integration_hooks as ih
    from . import script_schedules as ss
    held = []
    for s in ss.all_schedules():
        if s.get("enabled"):
            s["enabled"] = False
            s["paused_reason"] = "held by deploy clone"
            ss._save(s)
            held.append(s["id"])
    record["script_schedules"] = held
    hooks = []
    for h in ih.list_hooks():
        if h.get("enabled"):
            ih.set_enabled(h["slug"], False, by="deploy-clone")
            hooks.append(h["slug"])
    record["hooks"] = hooks


def import_clone(bundle: Path, passphrase: str, *, by: str = "system",
                 safety: bool = True) -> dict:
    """Replace this deploy's data with a clone bundle's. DESTRUCTIVE.

    Order: verify everything -> safety bundle -> stage files -> one DB
    transaction (rows + quarantine) -> swap file sets -> hold file-backed
    schedules and hooks. Anything that fails before the commit leaves the node
    exactly as it was.
    """
    from cryptography.fernet import Fernet
    from ..extensions import db
    from ..models import AppSetting
    from . import system_backup as sb

    bundle = Path(bundle)
    if _is_replica():
        raise CloneError("this node is a read-only standby; import on the primary")
    if not bundle.is_file():
        raise CloneError("no such bundle: %s" % bundle.name)

    ts = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    work = exports_dir().parent / ("clone-import-" + ts)
    work.mkdir(mode=0o700, parents=True)
    try:
        with tarfile.open(bundle, "r:gz") as tar:
            _extract(tar, work)
        manifest = _read_manifest(work)
        problems = check_bundle(work, manifest)
        if problems:
            raise CloneError("; ".join(problems))
        try:
            transfer = _unseal_key(json.loads((work / "transfer-key.json").read_text()),
                                   passphrase)
        except (OSError, ValueError) as exc:
            raise CloneError("bundle has no readable transfer key") from exc
        rk = _Rekeyer(Fernet(transfer), _node_fernet())

        safety_name = ""
        if safety:
            res = sb.create_backup(include_reports=True, label="pre-clone-safety")
            if not res.get("ok"):
                raise CloneError("safety bundle failed, nothing changed: %s"
                                 % res.get("detail", ""))
            safety_name = res["name"]

        # Stage the file sets next to their destinations: the swap after the
        # commit is then a rename, not an extraction that can fail halfway.
        sets = {n: (d, sub) for n, d, sub in
                _file_sets(bool(manifest.get("with_firmware")))}
        staged = {}
        for fname in manifest.get("files") or {}:
            if fname not in sets:
                continue
            d, _sub = sets[fname]
            tmp = d.parent / (".%s.clone-%s" % (d.name, ts))
            tmp.mkdir(parents=True)
            with tarfile.open(work / "files" / (fname + ".tar"), "r") as tar:
                _extract(tar, tmp)
            staged[fname] = tmp

        order = [t for t in db.metadata.sorted_tables
                 if t.name in (manifest.get("tables") or {})]
        kept = [(r.key, r.value) for r in db.session.query(AppSetting).all()
                if is_node_local_setting(r.key)]
        record = {"at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
                  "by": by, "bundle": bundle.name,
                  "source": manifest.get("source", {}).get("node", "")}
        counts = {}
        # The rows are replaced underneath the ORM. Objects already loaded
        # (the settings just read) would otherwise be merged as UPDATEs of
        # rows that no longer exist.
        db.session.expunge_all()
        try:
            for t in reversed(order):
                db.session.execute(t.delete())
            for t in order:
                counts[t.name] = _insert_table(t, _rows(work, t), rk)
            for key, value in kept:
                db.session.merge(AppSetting(key=key, value=value))
            # Every session opened before this commit names a user id of the
            # OLD users table; end them all (auth.session_epoch).
            from ..auth import session_epoch
            db.session.merge(AppSetting(key=session_epoch.KEY,
                                        value=session_epoch.new_value()))
            _quarantine_db(record)
            db.session.flush()
            _reset_sequences(order)
            db.session.commit()
        except Exception:
            db.session.rollback()
            for tmp in staged.values():
                shutil.rmtree(tmp, ignore_errors=True)
            raise

        prev = exports_dir().parent / ("clone-prev-" + ts)
        swapped = []
        for fname, tmp in staged.items():
            d, sub = sets[fname]
            parts = list(sub) if sub else [None]
            for part in parts:
                src = tmp / part if part else tmp
                dst = d / part if part else d
                keep = prev / fname / (part or "")
                if dst.exists():
                    keep.parent.mkdir(parents=True, exist_ok=True)
                    shutil.move(str(dst), str(keep))
                if src.exists():
                    dst.parent.mkdir(parents=True, exist_ok=True)
                    shutil.move(str(src), str(dst))
                elif part:
                    dst.mkdir(parents=True, exist_ok=True)
            shutil.rmtree(tmp, ignore_errors=True)
            swapped.append(fname)

        _quarantine_files(record)
        record["previous_files"] = str(prev) if prev.exists() else ""
        AppSetting.set(QUARANTINE_KEY, json.dumps(record))
        AppSetting.set(LAST_IMPORT_KEY, json.dumps(
            {"at": record["at"], "bundle": bundle.name, "by": by,
             "source": manifest.get("source", {}), "safety": safety_name}))
        unreadable = verify_secrets()
        _audit("deploy_clone.import", bundle.name,
               {"source": record["source"], "rows": sum(counts.values()),
                "rekey": rk.counts(), "safety": safety_name,
                "held_actions": len(record["actions"])})
        return {"ok": True, "rows": sum(counts.values()), "tables": len(counts),
                "files": swapped, "rekey": rk.counts(), "safety": safety_name,
                "quarantine": quarantine_summary(record),
                "previous_files": record["previous_files"],
                "unreadable_secrets": unreadable,
                "source": manifest.get("source", {})}
    finally:
        shutil.rmtree(work, ignore_errors=True)


def verify_secrets() -> list:
    """Every Fernet token in the database this node's key cannot open.

    Run after an import, so a clone that "succeeded" into unreadable
    credentials says so on the spot instead of at the first device sync."""
    import sqlalchemy as sa
    from cryptography.fernet import InvalidToken
    from ..extensions import db
    f = _node_fernet()
    bad = []
    for t in db.metadata.sorted_tables:
        cols = [c for c in t.columns
                if isinstance(c.type, (sa.String, sa.Text, sa.JSON))]
        if not cols:
            continue
        conn = db.session.connection().execution_options(yield_per=5000)
        for row in conn.execute(sa.select(*cols)).mappings():
            for c in cols:
                v = row[c.name]
                s = v if isinstance(v, str) else (json.dumps(v) if v else "")
                for m in _TOKEN_RX.finditer(s or ""):
                    try:
                        f.decrypt(m.group(0).encode())
                    except (InvalidToken, ValueError):
                        bad.append("%s.%s" % (t.name, c.name))
    return sorted(set(bad))


# ---------------------------------------------------------------------------
# quarantine
# ---------------------------------------------------------------------------

def quarantine_state() -> dict | None:
    from ..models import AppSetting
    raw = AppSetting.get(QUARANTINE_KEY)
    if not raw:
        return None
    try:
        return json.loads(raw)
    except ValueError:
        return None


def quarantine_summary(record: dict | None) -> dict:
    record = record or {}
    return {"actions": len(record.get("actions") or ()),
            "script_schedules": len(record.get("script_schedules") or ()),
            "hooks": len(record.get("hooks") or ()),
            "flags": sorted((record.get("flags") or {}))}


def release_quarantine(*, by: str = "system") -> dict:
    """Give back exactly what the import switched off -- nothing an operator
    disabled on the source comes back. Schedules restart from NOW: the next
    run is computed fresh, so the held period is not replayed."""
    from ..extensions import db
    from ..models import AppSetting, ScheduledAction
    from . import integration_hooks as ih
    from . import scheduler
    from . import script_schedules as ss
    record = quarantine_state()
    if record is None:
        raise CloneError("nothing is held: no clone quarantine on this node")
    if _is_replica():
        raise CloneError("this node is a read-only standby")
    now = datetime.utcnow()
    try:
        from . import settings_store
        tz = settings_store.tz_name()
    except Exception:  # noqa: BLE001
        tz = "UTC"
    released = 0
    for aid in record.get("actions") or ():
        a = db.session.get(ScheduledAction, aid)
        if a is None:
            continue
        a.enabled = True
        a.next_run = scheduler.compute_next_run(a.schedule_kind, a.schedule_dict,
                                                now, tz=tz)
        released += 1
    for key, value in (record.get("flags") or {}).items():
        row = db.session.get(AppSetting, key)
        if row is not None:
            row.value = value
    db.session.commit()
    schedules = 0
    for sid in record.get("script_schedules") or ():
        s = ss.get(sid)
        if s is not None:
            ss.set_enabled(s, True)
            schedules += 1
    hooks = 0
    for slug in record.get("hooks") or ():
        if ih.set_enabled(slug, True, by=by) is not None:
            hooks += 1
    row = db.session.get(AppSetting, QUARANTINE_KEY)
    if row is not None:
        db.session.delete(row)
        db.session.commit()
    _audit("deploy_clone.release", record.get("bundle", ""),
           {"actions": released, "script_schedules": schedules, "hooks": hooks})
    return {"ok": True, "actions": released, "script_schedules": schedules,
            "hooks": hooks, "flags": sorted(record.get("flags") or {})}


def status() -> dict:
    from ..models import AppSetting
    last = AppSetting.get(LAST_IMPORT_KEY)
    try:
        last = json.loads(last) if last else None
    except ValueError:
        last = None
    q = quarantine_state()
    return {"quarantine": q, "held": quarantine_summary(q) if q else None,
            "last_import": last, "exports": _listing("clone-exports"),
            "uploads": _listing("clone-imports")}


# ---------------------------------------------------------------------------
# console (Settings > Source of Truth & Backup > Deploy Clone)
# ---------------------------------------------------------------------------
# The web worker never exports or imports by itself. An import stops the very
# service that answers the page, and an export of a large deploy outlives a
# request; both are queued for the privileged runner (satom-updater), which
# runs the installed CLI -- the same code path as 'satom execute clone ...'.
# What runs here is cheap and read-only: listing, the manifest preflight, the
# passphrase check, and the release (a few rows, no service stops).

_WHERE = {"exports": "clone-exports", "uploads": "clone-imports"}


def _listing(sub: str) -> list:
    out = []
    d = _data_root() / sub
    if d.is_dir():
        for p in sorted(d.glob("satom-clone-*.tar.gz"), reverse=True):
            if p.is_symlink() or not p.is_file():
                continue
            st = p.stat()
            out.append({"name": p.name, "size": st.st_size,
                        "mtime": datetime.utcfromtimestamp(st.st_mtime)
                        .isoformat(timespec="seconds") + "Z"})
    return out


def new_passphrase() -> str:
    from . import recovery_seal
    return recovery_seal.generate_passphrase(6)


def bundle_path(where: str, name: str) -> Path | None:
    """The bundle ``name`` in exports|uploads, or None. Names are checked
    before a path is built: they arrive from a URL or a form."""
    sub = _WHERE.get(where)
    if not sub or not isinstance(name, str) or not _NAME_RX.match(name):
        return None
    p = _data_root() / sub / name
    if p.is_symlink() or not p.is_file():
        return None
    return p


def delete_bundle(where: str, name: str) -> None:
    p = bundle_path(where, name)
    if p is None:
        raise CloneError("no such bundle: %s" % name)
    p.unlink()
    _audit("deploy_clone.delete", name, {"where": where})


def _peek(path: Path) -> tuple:
    """(manifest, transfer-key envelope) from the head of the archive.

    Read as a stream and stopped as soon as both are in hand: the export writes
    them first, so a preflight of a large bundle decompresses kilobytes, not
    the whole file. Anything else in front of them is a bundle this module did
    not write.
    """
    found = {}
    try:
        with tarfile.open(path, "r|gz") as tar:
            for i, m in enumerate(tar):
                if m.name in ("manifest.json", "transfer-key.json") and m.isfile() \
                        and m.size < 4 * 1024 * 1024:
                    found[m.name] = json.loads(tar.extractfile(m).read().decode("utf-8"))
                if len(found) == 2 or i >= 4:
                    break
    except (tarfile.TarError, OSError, EOFError, ValueError) as exc:
        raise CloneError("not a readable clone bundle: %s" % exc) from exc
    manifest = found.get("manifest.json")
    if not isinstance(manifest, dict) or manifest.get("format") != FORMAT:
        raise CloneError("not a SATOM clone bundle (format %r)"
                         % ((manifest or {}).get("format")
                            if isinstance(manifest, dict) else None))
    keydoc = found.get("transfer-key.json")
    if not isinstance(keydoc, dict):
        raise CloneError("bundle has no readable transfer key")
    return manifest, keydoc


def preflight(path: Path, passphrase: str | None = None) -> dict:
    """What an import of ``path`` would bring, and why it cannot happen here.

    With a passphrase the transfer key is opened as well; a wrong one raises
    (one message for wrong and altered, as at import). The checksums are NOT
    verified here -- that needs the whole archive, and the import does it
    before it writes anything.
    """
    path = Path(path)
    manifest, keydoc = _peek(path)
    if passphrase is not None:
        _unseal_key(keydoc, passphrase)
    tables = manifest.get("tables") or {}
    return {"name": path.name, "size": path.stat().st_size,
            "source": {k: (manifest.get("source") or {}).get(k)
                       for k in ("node", "version", "alembic")},
            "created": manifest.get("created"),
            "with_firmware": bool(manifest.get("with_firmware")),
            "tables": len(tables),
            "rows": sum(int((t or {}).get("rows") or 0) for t in tables.values()),
            "files": {k: int((v or {}).get("files") or 0)
                      for k, v in (manifest.get("files") or {}).items()},
            "problems": compat_problems(manifest)}


def save_upload(stream, filename: str) -> dict:
    """Store an uploaded bundle in the import inbox and preflight it.

    Written 0600 under a temporary name and renamed only once it reads as a
    clone bundle: a half-uploaded or foreign file never shows up as importable.
    """
    from . import system_backup as sb
    name = Path(filename or "").name
    if not _NAME_RX.match(name):
        raise CloneError("expected a file named satom-clone-<node>-<time>.tar.gz "
                         "(as the export writes it)")
    inbox = imports_dir()
    dest = inbox / name
    if dest.exists() or dest.is_symlink():
        raise CloneError("%s is already uploaded; delete it first" % name)
    tmp = inbox / (".upload-%s" % os.urandom(6).hex())
    try:
        with sb._open_private(tmp) as fh:
            shutil.copyfileobj(stream, fh, 1 << 20)
        _peek(tmp)
        tmp.rename(dest)
    finally:
        if tmp.exists():
            tmp.unlink()
    _audit("deploy_clone.upload", name, {"size": dest.stat().st_size})
    return preflight(dest)


def _clone_jobs() -> list:
    from . import self_update as su
    out = []
    if su.STATUS_DIR.is_dir():
        for p in su.STATUS_DIR.glob("*.json"):
            try:
                d = json.loads(p.read_text())
            except (OSError, ValueError):
                continue
            if isinstance(d, dict) and d.get("kind") == RUNNER_KIND:
                out.append(d)
    out.sort(key=lambda d: d.get("updated_at") or "", reverse=True)
    return out


def recent_jobs(limit: int = 10) -> list:
    return _clone_jobs()[:limit]


def job_status(uid: str) -> dict | None:
    from . import self_update as su
    st = su.update_status(uid)
    return st if isinstance(st, dict) and st.get("kind") == RUNNER_KIND else None


def request_job(action: str, *, by: str, passphrase: str, name: str | None = None,
                with_firmware: bool = False) -> str:
    """Queue an export or an import for the privileged runner. Returns its id.

    Everything that can be refused here is refused here -- standby, container,
    a job already in flight, a bundle that is not importable, a wrong
    passphrase -- so the operator hears it in the page. The runner checks the
    shape of the request again on its side.

    The passphrase travels in the REQUEST file only: the runner deletes that
    file before it does anything else, data/update-requests/ is excluded from
    the HA datasync, and nothing writes it to a status file.
    """
    from datetime import timedelta
    import uuid
    from .. import runtime
    from . import self_update as su

    if action not in RUNNER_ACTIONS:
        raise CloneError("unknown clone action %r" % (action,))
    if runtime.is_container_runtime():
        raise CloneError("the container runtime has no privileged runner; "
                         "copy the data with the CLI on a host install")
    if _is_replica():
        raise CloneError("this node is a read-only standby; use the primary")
    stale = (datetime.utcnow() - timedelta(hours=3)).isoformat()
    for j in _clone_jobs():
        if j.get("state") in ("queued", "running") and \
                (j.get("updated_at") or "") > stale:
            raise CloneError("a clone %s is already %s (%s); wait for it to end"
                             % (j.get("action", "job"), j["state"], j.get("id")))
    if not passphrase or len(passphrase) < MIN_PASSPHRASE_LEN:
        raise CloneError("the passphrase must be at least %d characters"
                         % MIN_PASSPHRASE_LEN)
    req = {"kind": RUNNER_KIND, "action": action, "requested_by": by,
           "passphrase": passphrase}
    if action == "import":
        p = bundle_path("uploads", name or "")
        if p is None:
            raise CloneError("no uploaded bundle named %r" % (name,))
        pf = preflight(p, passphrase)
        if pf["problems"]:
            raise CloneError("; ".join(pf["problems"]))
        req["bundle"] = p.name
    else:
        req["with_firmware"] = bool(with_firmware)

    su.REQ_DIR.mkdir(parents=True, exist_ok=True)
    su.STATUS_DIR.mkdir(parents=True, exist_ok=True)
    uid = datetime.utcnow().strftime("%Y%m%d-%H%M%S-clone-") + uuid.uuid4().hex[:6]
    node, role = su.this_node_name(), su.node_role()
    req.update(id=uid, requested_at=datetime.utcnow().isoformat() + "Z",
               node=node, role=role, origin="settings-deploy-clone")
    # Status first, as for service actions: an import restarts the worker that
    # wrote this, and a request with no status row is a click that vanished.
    (su.STATUS_DIR / (uid + ".json")).write_text(json.dumps({
        "id": uid, "state": "queued", "steps": [], "kind": RUNNER_KIND,
        "action": action, "target": req.get("bundle") or "export",
        "requested_by": by, "node": node, "role": role,
        "origin": "settings-deploy-clone",
        "updated_at": datetime.utcnow().isoformat() + "Z"}))
    tmp = su.REQ_DIR / ("." + uid + ".tmp")
    with open(os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600),
              "w") as fh:
        fh.write(json.dumps(req))
    tmp.rename(su.REQ_DIR / (uid + ".json"))
    _audit("deploy_clone.request", req.get("bundle") or "export",
           {"action": action, "id": uid, "with_firmware": bool(with_firmware)})
    return uid


def _audit(action: str, target: str, extra: dict) -> None:
    try:
        from .audit import log_action
        log_action(action, target, extra)
    except Exception:  # noqa: BLE001 - audit is best-effort
        pass
