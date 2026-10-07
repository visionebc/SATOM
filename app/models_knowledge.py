"""Knowledge imported from signed packs that has no other home.

``knowledge_signature_meta`` holds PUBLIC FortiGuard encyclopedia metadata
about signature ids (name, severity, category, CVEs, references). Signatures
themselves never travel in a pack and are never stored here: an appliance
reports the ids it carries, this table only explains them.

Rows arrive from the ``signature-meta`` section of an API pack
(``services/api_pack.py``) and say where they came from in ``origin``:
``local`` | ``pack:api_pack:<pack>`` | ``pack:knowledge:<pack>``. A ``local``
row is never replaced by a pack; a pack row is replaced by a pack of the same
or a higher-ranked lane when its content changed.
"""
from __future__ import annotations

from datetime import datetime

from .extensions import db


class KnowledgeSignatureMeta(db.Model):
    """Public metadata of one signature id of one product."""

    __tablename__ = "knowledge_signature_meta"
    __table_args__ = (
        db.UniqueConstraint("product", "sig_id", name="uq_knowledge_signature_meta_product_sig"),
    )

    id = db.Column(db.Integer, primary_key=True)
    product = db.Column(db.String(32), nullable=False)
    sig_id = db.Column(db.String(64), nullable=False)
    name = db.Column(db.String(255), nullable=False, default="")
    severity = db.Column(db.String(32), nullable=False, default="")
    category = db.Column(db.String(128), nullable=False, default="")
    cve = db.Column(db.JSON, nullable=True)
    references = db.Column(db.JSON, nullable=True)
    url = db.Column(db.String(512), nullable=False, default="")
    summary = db.Column(db.Text, nullable=False, default="")
    #: ``local`` | ``pack:<lane>:<pack name>``
    origin = db.Column(db.String(128), nullable=False, default="local")
    imported_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


__all__ = ["KnowledgeSignatureMeta"]
