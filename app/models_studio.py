"""Python Studio data: data stores, connections, apps, app runs, user groups.

Administrator > Studio > Python Studio (2026-10-20). What lives here:

* **Data stores** -- tables an administrator defines in the UI. Rows are JSON
  documents checked against the store's column list (``services.studio_store``);
  nothing here ever takes SQL or DDL from a user, so a data store cannot reach
  any other SATOM table. They live in the SATOM database, so they replicate to
  the standby and travel in every backup like the rest of the configuration.
* **Connections** -- named external APIs (``http``) and external PostgreSQL
  databases (``postgres``). The secret is never a column of this table: it is
  an ``app_settings`` row (Fernet) or the vault, like every other setting
  secret (``services.studio_connections``).
* **API Catalog** -- APIs someone publishes, one frozen endpoint list per
  version; an HTTP connection can be pinned to one (``services.studio_apis``).
* **Apps** -- a form, a diagram and an output, published into Operations >
  Plugins for the ADOMs and the people the administrator picks
  (``services.studio_apps``, ``services.studio_flow``).
* **User groups** -- who may use an app, besides named users.
"""
from __future__ import annotations

import json
from datetime import datetime

from .extensions import db


def _loads(raw, default):
    try:
        v = json.loads(raw) if raw else default
    except (TypeError, ValueError):
        return default
    return v if isinstance(v, type(default)) else default


# --------------------------------------------------------------------------- #
#  Data stores                                                                 #
# --------------------------------------------------------------------------- #
class StudioDataStore(db.Model):
    __tablename__ = "studio_datastores"

    id = db.Column(db.Integer, primary_key=True)
    slug = db.Column(db.String(48), unique=True, nullable=False, index=True)
    name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=False, default="")
    #: JSON list of {name, label, type, required}; see studio_store.COLUMN_TYPES
    columns_json = db.Column(db.Text, nullable=False, default="[]")
    created_by = db.Column(db.String(64), nullable=False, default="")
    updated_by = db.Column(db.String(64), nullable=False, default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow,
                           onupdate=datetime.utcnow, nullable=False)

    @property
    def columns(self) -> list:
        return _loads(self.columns_json, [])


class StudioRow(db.Model):
    __tablename__ = "studio_rows"

    id = db.Column(db.Integer, primary_key=True)
    store_id = db.Column(db.Integer, db.ForeignKey("studio_datastores.id", ondelete="CASCADE"),
                         nullable=False, index=True)
    data_json = db.Column(db.Text, nullable=False, default="{}")
    created_by = db.Column(db.String(64), nullable=False, default="")
    updated_by = db.Column(db.String(64), nullable=False, default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow,
                           onupdate=datetime.utcnow, nullable=False)

    @property
    def data(self) -> dict:
        return _loads(self.data_json, {})


# --------------------------------------------------------------------------- #
#  Connections                                                                 #
# --------------------------------------------------------------------------- #
class StudioConnection(db.Model):
    __tablename__ = "studio_connections"

    id = db.Column(db.Integer, primary_key=True)
    slug = db.Column(db.String(48), unique=True, nullable=False, index=True)
    name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=False, default="")
    kind = db.Column(db.String(16), nullable=False, default="http")      # http | postgres
    #: http: the base URL every call stays under. postgres: unused.
    base_url = db.Column(db.String(500), nullable=False, default="")
    #: postgres: host / port / database. http: unused.
    host = db.Column(db.String(255), nullable=False, default="")
    port = db.Column(db.Integer, nullable=True)
    database = db.Column(db.String(128), nullable=False, default="")
    #: none | basic | bearer | api_key | oauth2 (client credentials) | password (postgres)
    auth = db.Column(db.String(16), nullable=False, default="none")
    username = db.Column(db.String(255), nullable=False, default="")
    header_name = db.Column(db.String(128), nullable=False, default="")
    token_url = db.Column(db.String(500), nullable=False, default="")
    scope = db.Column(db.String(500), nullable=False, default="")
    verify_tls = db.Column(db.Boolean, nullable=False, default=True)
    timeout = db.Column(db.Integer, nullable=False, default=20)
    #: http: the API Catalog version this connection speaks (published or
    #: deprecated, never a draft). Set = app steps and scripts reach only that
    #: version's endpoints, and can call them by id.
    api_version_id = db.Column(db.Integer, db.ForeignKey("studio_api_versions.id"),
                               nullable=True, index=True)
    created_by = db.Column(db.String(64), nullable=False, default="")
    updated_by = db.Column(db.String(64), nullable=False, default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow,
                           onupdate=datetime.utcnow, nullable=False)

    api_version = db.relationship("StudioApiVersion", lazy="joined")


# --------------------------------------------------------------------------- #
#  API Catalog (FA-0006): APIs someone publishes, one row per version          #
# --------------------------------------------------------------------------- #
class StudioApi(db.Model):
    __tablename__ = "studio_apis"

    id = db.Column(db.Integer, primary_key=True)
    slug = db.Column(db.String(48), unique=True, nullable=False, index=True)
    name = db.Column(db.String(120), nullable=False)
    #: Who publishes it (a team, a vendor) and where its own docs live.
    owner = db.Column(db.String(120), nullable=False, default="")
    docs_url = db.Column(db.String(500), nullable=False, default="")
    description = db.Column(db.Text, nullable=False, default="")
    created_by = db.Column(db.String(64), nullable=False, default="")
    updated_by = db.Column(db.String(64), nullable=False, default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow,
                           onupdate=datetime.utcnow, nullable=False)

    versions = db.relationship("StudioApiVersion", back_populates="api", lazy="select",
                               cascade="all, delete-orphan")


class StudioApiVersion(db.Model):
    """One version of an API. A draft is edited; publishing freezes it for
    good (its endpoints never change again, and it is never deleted), so a
    connection pinned to it means the same thing tomorrow."""
    __tablename__ = "studio_api_versions"
    __table_args__ = (db.UniqueConstraint("api_id", "version", name="uq_studio_api_version"),)

    STATUSES = ("draft", "published", "deprecated")

    id = db.Column(db.Integer, primary_key=True)
    api_id = db.Column(db.Integer, db.ForeignKey("studio_apis.id", ondelete="CASCADE"),
                       nullable=False, index=True)
    version = db.Column(db.String(32), nullable=False)
    status = db.Column(db.String(16), nullable=False, default="draft")
    #: openapi | manual -- how the endpoint list was last filled.
    source = db.Column(db.String(16), nullable=False, default="manual")
    #: The path prefix the document's servers/basePath name (informational:
    #: the connection's base URL decides where calls go).
    base_path = db.Column(db.String(200), nullable=False, default="")
    spec_sha256 = db.Column(db.String(64), nullable=False, default="")
    #: JSON list of operations (services.studio_api_spec.clean_operation).
    operations_json = db.Column(db.Text, nullable=False, default="[]")
    notes = db.Column(db.Text, nullable=False, default="")
    created_by = db.Column(db.String(64), nullable=False, default="")
    updated_by = db.Column(db.String(64), nullable=False, default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow,
                           onupdate=datetime.utcnow, nullable=False)
    published_by = db.Column(db.String(64), nullable=False, default="")
    published_at = db.Column(db.DateTime, nullable=True)

    api = db.relationship("StudioApi", back_populates="versions")

    @property
    def operations(self) -> list:
        return _loads(self.operations_json, [])

    @property
    def label(self) -> str:
        return "%s %s" % (self.api.slug if self.api else "?", self.version)


# --------------------------------------------------------------------------- #
#  User groups (who may use an app)                                           #
# --------------------------------------------------------------------------- #
user_group_members = db.Table(
    "user_group_members",
    db.Column("group_id", db.Integer, db.ForeignKey("user_groups.id", ondelete="CASCADE"),
              primary_key=True),
    db.Column("user_id", db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"),
              primary_key=True),
)


class UserGroup(db.Model):
    __tablename__ = "user_groups"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, nullable=False)
    description = db.Column(db.Text, nullable=False, default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    members = db.relationship("User", secondary=user_group_members, lazy="select",
                              order_by="User.username")


# --------------------------------------------------------------------------- #
#  Apps                                                                        #
# --------------------------------------------------------------------------- #
class StudioApp(db.Model):
    __tablename__ = "studio_apps"

    STATUSES = ("draft", "published")

    id = db.Column(db.Integer, primary_key=True)
    slug = db.Column(db.String(48), unique=True, nullable=False, index=True)
    name = db.Column(db.String(120), nullable=False)
    icon = db.Column(db.String(32), nullable=False, default="bi-app-indicator")
    description = db.Column(db.Text, nullable=False, default="")
    status = db.Column(db.String(16), nullable=False, default="draft")
    #: JSON list of ADOM keys the app is drawn in; ["*"] = every ADOM.
    adoms_json = db.Column(db.Text, nullable=False, default="[]")
    #: JSON {"groups": [ids], "users": [ids]}: who may use it.
    access_json = db.Column(db.Text, nullable=False, default="{}")
    #: The DRAFT: form fields, diagram, output actions.
    fields_json = db.Column(db.Text, nullable=False, default="[]")
    graph_json = db.Column(db.Text, nullable=False, default="{}")
    #: The satom.plugin/1 package version last imported, and its trusted
    #: signer key id ("" = unsigned). NULL for an app authored here.
    pkg_version = db.Column(db.String(32), nullable=True)
    pkg_signer = db.Column(db.String(64), nullable=True)
    actions_json = db.Column(db.Text, nullable=False, default="[]")
    #: The look of the app (services.studio_design): {theme, page, result}.
    #: "{}" = SATOM's standard layout. 2026-10-23.
    design_json = db.Column(db.Text, nullable=False, default="{}", server_default="{}")
    #: "flow" (form + diagram, run here) or "script" (the entry of a Script
    #: Library script: the code, its form and its versions stay in
    #: data/scripts/<script_slug>, run by the sandbox runner). 2026-10-23.
    kind = db.Column(db.String(16), nullable=False, default="flow", server_default="flow")
    script_slug = db.Column(db.String(48), nullable=True)
    #: False = disabled: out of every menu and no run starts; nothing is lost.
    enabled = db.Column(db.Boolean, nullable=False, default=True, server_default=db.true())
    #: The PUBLISHED snapshot ({version, fields, graph, actions, at, by, note})
    #: operators run. Editing the draft never changes it.
    published_json = db.Column(db.Text, nullable=False, default="{}")
    version = db.Column(db.Integer, nullable=False, default=0)
    created_by = db.Column(db.String(64), nullable=False, default="")
    updated_by = db.Column(db.String(64), nullable=False, default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow,
                           onupdate=datetime.utcnow, nullable=False)
    published_at = db.Column(db.DateTime, nullable=True)

    @property
    def adoms(self) -> list:
        return [str(x) for x in _loads(self.adoms_json, [])]

    @property
    def access(self) -> dict:
        a = _loads(self.access_json, {})
        return {"groups": [int(x) for x in a.get("groups") or [] if str(x).isdigit()],
                "users": [int(x) for x in a.get("users") or [] if str(x).isdigit()]}

    @property
    def fields(self) -> list:
        return _loads(self.fields_json, [])

    @property
    def graph(self) -> dict:
        g = _loads(self.graph_json, {})
        return {"nodes": g.get("nodes") or [], "edges": g.get("edges") or []}

    @property
    def actions(self) -> list:
        return _loads(self.actions_json, [])

    @property
    def published(self) -> dict:
        return _loads(self.published_json, {})

    @property
    def design(self) -> dict:
        d = _loads(self.design_json, {})
        return d if isinstance(d, dict) else {}


class StudioAppAsset(db.Model):
    """An image uploaded to an app's design (services.studio_design): kept in
    the database so it replicates with the app and travels in its package.
    The type is sniffed from the bytes at upload (PNG/JPEG/GIF/WebP only)."""
    __tablename__ = "studio_app_assets"
    __table_args__ = (db.UniqueConstraint("app_id", "sha256", name="uq_studio_app_asset"),)

    id = db.Column(db.Integer, primary_key=True)
    app_id = db.Column(db.Integer, db.ForeignKey("studio_apps.id", ondelete="CASCADE"),
                       nullable=False, index=True)
    sha256 = db.Column(db.String(64), nullable=False)
    mime = db.Column(db.String(32), nullable=False)
    name = db.Column(db.String(120), nullable=False, default="")
    size = db.Column(db.Integer, nullable=False, default=0)
    data = db.Column(db.LargeBinary, nullable=False)
    created_by = db.Column(db.String(64), nullable=False, default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class StudioAppRun(db.Model):
    __tablename__ = "studio_app_runs"

    id = db.Column(db.Integer, primary_key=True)
    app_id = db.Column(db.Integer, db.ForeignKey("studio_apps.id", ondelete="CASCADE"),
                       nullable=False, index=True)
    #: The published version run, or 0 for a test run of the draft.
    version = db.Column(db.Integer, nullable=False, default=0)
    armed = db.Column(db.Boolean, nullable=False, default=True)
    status = db.Column(db.String(16), nullable=False, default="running")  # running|done|failed
    user = db.Column(db.String(64), nullable=False, default="", index=True)
    product = db.Column(db.String(32), nullable=False, default="")
    inputs_json = db.Column(db.Text, nullable=False, default="{}")     # password values masked
    outputs_json = db.Column(db.Text, nullable=False, default="[]")
    vars_json = db.Column(db.Text, nullable=False, default="{}")
    steps_json = db.Column(db.Text, nullable=False, default="[]")
    error = db.Column(db.Text, nullable=False, default="")
    started_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    finished_at = db.Column(db.DateTime, nullable=True)

    @property
    def outputs(self) -> list:
        return _loads(self.outputs_json, [])

    @property
    def steps(self) -> list:
        return _loads(self.steps_json, [])

    @property
    def inputs(self) -> dict:
        return _loads(self.inputs_json, {})

    @property
    def vars(self) -> dict:
        return _loads(self.vars_json, {})
