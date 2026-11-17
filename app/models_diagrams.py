"""Diagram Studio -- the tables behind Operations' diagram library and the
first-level Diagrams menu.

Why a module of its own: the diagrams are SATOM's own documents, not device
configuration, and nothing else in the schema refers to them. Five tables:

* ``diagram_folders`` -- ONE nested tree, shared by the Studio library and the
  sidebar's Diagrams menu (a published diagram is drawn under its folder).
  ``parent_id`` is ON DELETE RESTRICT: a folder is deleted only when empty,
  never by cascading through its children.
* ``diagrams`` -- the document's identity and its publication state. The
  content lives in ``diagram_versions``; ``current_version`` is the number the
  editor's optimistic lock compares against.
* ``diagram_versions`` -- append-only, content-addressed history: the gzip of
  the canonical ``satom.diagram/1`` JSON and its sha256. A save whose content
  is identical to the current version writes no row.
* ``diagram_imports`` -- one row per uploaded file. The web worker never parses
  the file: it stores the bytes, queues a request for the jailed runner
  (``services/diagram_runner.py``, no database) and reads its status file back
  into this row lazily.
* ``diagram_libraries`` -- operator symbol libraries (built-in ones ship with
  the engine and are never stored here).

Every row a reader may see carries ``adom`` (``product_scope.stamp()`` at
creation), so the same scoping rule as every other ADOM-scoped table applies:
a console sees its own ADOM's rows, Global sees them all.
"""
from __future__ import annotations

from datetime import datetime

from .extensions import db


def _now() -> datetime:
    return datetime.utcnow()


class DiagramFolder(db.Model):
    __tablename__ = "diagram_folders"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False)
    parent_id = db.Column(db.Integer, db.ForeignKey("diagram_folders.id", ondelete="RESTRICT"),
                          nullable=True, index=True)
    position = db.Column(db.Integer, nullable=False, default=0, server_default="0")
    adom = db.Column(db.String(32), nullable=False, default="", server_default="", index=True)
    created_by = db.Column(db.String(64), nullable=False, default="", server_default="")
    created_at = db.Column(db.DateTime, nullable=False, default=_now)
    updated_at = db.Column(db.DateTime, nullable=False, default=_now, onupdate=_now)


class Diagram(db.Model):
    __tablename__ = "diagrams"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False, default="", server_default="")
    folder_id = db.Column(db.Integer, db.ForeignKey("diagram_folders.id", ondelete="SET NULL"),
                          nullable=True, index=True)
    adom = db.Column(db.String(32), nullable=False, default="", server_default="", index=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    published = db.Column(db.Boolean, nullable=False, default=False)
    published_at = db.Column(db.DateTime, nullable=True)
    published_version = db.Column(db.Integer, nullable=True)
    current_version = db.Column(db.Integer, nullable=False, default=0, server_default="0")
    source_format = db.Column(db.String(32), nullable=False, default="", server_default="")
    source_filename = db.Column(db.String(255), nullable=False, default="", server_default="")
    source_sha256 = db.Column(db.String(64), nullable=False, default="", server_default="")
    created_by = db.Column(db.String(64), nullable=False, default="", server_default="")
    created_at = db.Column(db.DateTime, nullable=False, default=_now)
    updated_by = db.Column(db.String(64), nullable=False, default="", server_default="")
    updated_at = db.Column(db.DateTime, nullable=False, default=_now, onupdate=_now)


class DiagramVersion(db.Model):
    __tablename__ = "diagram_versions"
    __table_args__ = (
        db.UniqueConstraint("diagram_id", "number", name="uq_diagram_versions_number"),
        db.Index("ix_diagram_versions_sha", "diagram_id", "sha256"),
    )

    id = db.Column(db.Integer, primary_key=True)
    diagram_id = db.Column(db.Integer, db.ForeignKey("diagrams.id", ondelete="CASCADE"),
                           nullable=False)
    number = db.Column(db.Integer, nullable=False)
    sha256 = db.Column(db.String(64), nullable=False)
    doc_gz = db.Column(db.LargeBinary, nullable=False)
    stats_json = db.Column(db.Text, nullable=False, default="{}", server_default="{}")
    note = db.Column(db.String(500), nullable=False, default="", server_default="")
    created_by = db.Column(db.String(64), nullable=False, default="", server_default="")
    created_at = db.Column(db.DateTime, nullable=False, default=_now)


class DiagramImport(db.Model):
    __tablename__ = "diagram_imports"

    id = db.Column(db.String(40), primary_key=True)
    status = db.Column(db.String(16), nullable=False, default="queued", server_default="queued")
    filename = db.Column(db.String(255), nullable=False, default="", server_default="")
    format = db.Column(db.String(32), nullable=False, default="", server_default="")
    source_sha256 = db.Column(db.String(64), nullable=False, default="", server_default="")
    options_json = db.Column(db.Text, nullable=False, default="{}", server_default="{}")
    error = db.Column(db.String(1000), nullable=False, default="", server_default="")
    adom = db.Column(db.String(32), nullable=False, default="", server_default="", index=True)
    created_by = db.Column(db.String(64), nullable=False, default="", server_default="")
    created_at = db.Column(db.DateTime, nullable=False, default=_now)
    finished_at = db.Column(db.DateTime, nullable=True)
    diagram_id = db.Column(db.Integer, db.ForeignKey("diagrams.id", ondelete="SET NULL"),
                           nullable=True)


class DiagramLibrary(db.Model):
    __tablename__ = "diagram_libraries"

    id = db.Column(db.Integer, primary_key=True)
    lib_id = db.Column(db.String(48), nullable=False, unique=True)
    label = db.Column(db.String(80), nullable=False)
    family = db.Column(db.String(32), nullable=False, default="generic", server_default="generic")
    library_json = db.Column(db.Text, nullable=False)
    svgs_gz = db.Column(db.LargeBinary, nullable=False)
    created_by = db.Column(db.String(64), nullable=False, default="", server_default="")
    created_at = db.Column(db.DateTime, nullable=False, default=_now)
