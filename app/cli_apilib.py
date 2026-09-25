"""``flask apilib`` — operator commands for the API library.

Every write goes through ``api_library.ingest``, so each command here is safe
to re-run: identical evidence only bumps a confirmation counter. The vendor and
FortiAuthenticator adapters are imported lazily inside their commands, so a
missing optional adapter breaks that one command and not the whole CLI.
"""
from __future__ import annotations

import gzip
import json
import os

import click
from flask import current_app
from flask.cli import AppGroup

apilib_cli = AppGroup("apilib", help="API library: backfill, import and inspect evidence.")


def _default_data_root() -> str:
    return os.path.join(os.path.dirname(current_app.root_path), "data")


def _print(obj) -> None:
    click.echo(json.dumps(obj, indent=1, sort_keys=True, default=str))


@apilib_cli.command("backfill")
@click.option("--data-root", default=None, type=click.Path(file_okay=False),
              help="Directory holding rediscovery/, field_schemas/ and api_matrix/ "
                   "(default: the installation's data/).")
@click.option("--product", "products", multiple=True,
              help="Limit to one product (repeatable).")
def backfill_cmd(data_root, products):
    """Ingest every on-disk evidence store. Safe to run repeatedly."""
    from .services import api_library
    root = data_root or _default_data_root()
    if not os.path.isdir(root):
        raise click.ClickException("%s is not a directory" % root)
    _print(api_library.backfill(root, products=list(products) or None))


@apilib_cli.command("import-vendor")
@click.argument("path", type=click.Path(exists=True, file_okay=False))
def import_vendor_cmd(path):
    """Import an extracted vendor Ansible collection (fortios, fortianalyzer)."""
    from .services import api_library
    from .services import apilib_vendor
    try:
        docs = apilib_vendor.evidence_from_ansible_collection(path)
    except ValueError as exc:
        raise click.ClickException(str(exc))
    if not docs:
        click.echo("%s carries no version data; nothing imported." % path)
        return
    _print([dict(api_library.ingest(d), product=d.get("product"),
                 origin_ref=d.get("origin_ref")) for d in docs])


@apilib_cli.command("ingest-file")
@click.argument("path", type=click.Path(exists=True, dir_okay=False))
def ingest_file_cmd(path):
    """Ingest one evidence document (plain or gzipped JSON, or a list of them)."""
    from .services import api_library
    with open(path, "rb") as fh:
        raw = fh.read()
    data = gzip.decompress(raw) if raw[:2] == b"\x1f\x8b" else raw
    try:
        doc = json.loads(data.decode("utf-8"))
    except ValueError as exc:
        raise click.ClickException("%s is not JSON: %s" % (path, exc))
    docs = doc if isinstance(doc, list) else [doc]
    try:
        # The raw file is stored with the evidence only when it IS that one
        # document; a list file would attach the whole list to each member.
        _print([api_library.ingest(d, raw=raw if len(docs) == 1 else None) for d in docs])
    except ValueError as exc:
        raise click.ClickException(str(exc))


@apilib_cli.command("harvest-fac")
@click.option("--appliance", "name", default=None,
              help="Appliance name (default: every FortiAuthenticator).")
def harvest_fac_cmd(name):
    """Harvest the live Tastypie schema of FortiAuthenticator appliance(s)."""
    from .models import Appliance
    from .services import api_library
    from .services import apilib_fac
    q = Appliance.query.filter_by(kind="fortiauthenticator")
    if name:
        q = q.filter_by(name=name)
    targets = q.order_by(Appliance.name).all()
    if not targets:
        raise click.ClickException("no FortiAuthenticator appliance%s"
                                   % (" named %r" % name if name else ""))
    results = []
    for ap in targets:
        raw: dict = {}
        try:
            doc = apilib_fac.harvest(ap, raw=raw)
        except Exception as exc:  # noqa: BLE001 — one box must not stop the rest
            results.append({"appliance": ap.name, "error": "%s: %s" % (type(exc).__name__, exc)})
            continue
        res = api_library.ingest(doc, raw=raw or None)
        results.append({"appliance": ap.name, **res})
    _print(results)


@apilib_cli.command("status")
def status_cmd():
    """Counts per product, per source and per build."""
    from sqlalchemy import func, select

    from .extensions import db
    from .models_apilib import ApiLibBuild, ApiLibEvidence
    from .services import api_library

    for p in api_library.products():
        click.echo("%-20s builds=%-4d endpoints=%-5d evidence=%-4d %s%s" % (
            p["product"], p["builds"], p["endpoints"], p["evidence"],
            " ".join("%s:%d" % kv for kv in sorted(p["evidence_by_source"].items())),
            "  (catalog only)" if p["catalog_only"] else ""))
    rows = db.session.execute(
        select(ApiLibBuild.product, ApiLibBuild.version, ApiLibEvidence.source,
               func.count(ApiLibEvidence.id))
        .join(ApiLibEvidence, ApiLibEvidence.build_id == ApiLibBuild.id)
        .group_by(ApiLibBuild.product, ApiLibBuild.version, ApiLibEvidence.source)).all()
    if rows:
        click.echo("")
        from .services import firmware_versions as fv
        for product, version, source, n in sorted(
                rows, key=lambda r: (r[0], fv.sort_key(r[1]), r[2])):
            click.echo("  %-20s %-12s %-14s %d" % (product, version, source, n))
