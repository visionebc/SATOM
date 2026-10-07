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


@apilib_cli.command("schema-harvest")
@click.argument("appliance")
@click.option("--lab", is_flag=True, default=False,
              help="LAB box only: record first-row values as defaults (summary.lab).")
@click.option("--no-probe", is_flag=True, default=False,
              help="Skip the REST shape probe of the tree objects the library lacks.")
def schema_harvest_cmd(appliance, lab, no_probe):
    """Harvest one appliance's CLI schema (tree + show full-configuration) and
    probe the REST paths the library lacks. APPLIANCE is an id or a name."""
    from .models import Appliance
    from .services import schema_harvest
    ap = None
    if str(appliance).isdigit():
        ap = Appliance.query.get(int(appliance))
    if ap is None:
        ap = Appliance.query.filter_by(name=appliance).first()
    if ap is None:
        raise click.ClickException("no appliance %r" % appliance)
    res = schema_harvest.harvest(ap, lab=lab, probe=not no_probe)
    _print(res)
    if not res.get("ok"):
        raise SystemExit(1)


def compat_doc(product: str, base: str, target: str, limit: int = 200) -> dict:
    """What changes from ``base`` to ``target``, both channels, as one JSON doc
    (``satom execute apilib compat``). Lists are capped at ``limit``."""
    from .services import api_library

    cmp_ = api_library.compare(product, base, target)
    ch = cmp_.get("channels") or {}
    tree = ch.get("tree") or {}
    eps = tree.get("endpoints") or {}
    renames = [{"endpoint": k, **c} for k, e in sorted(eps.items())
               for c in e.get("rename_candidates") or []]
    options = [{"endpoint": k, **o} for k, e in sorted(eps.items())
               for o in e.get("options") or []]
    return {
        "product": product, "base": cmp_["base"], "target": cmp_["target"],
        "base_measured": cmp_["base_measured"], "target_measured": cmp_["target_measured"],
        "rest": {"totals": cmp_["totals"],
                 "endpoints_added": [e["endpoint"] for e in cmp_["endpoints_added"]][:limit],
                 "endpoints_removed": [e["endpoint"] for e in cmp_["endpoints_removed"]][:limit]},
        "tree": ({"totals": tree.get("totals") or {},
                  "endpoints_added": (tree.get("endpoints_added") or [])[:limit],
                  "endpoints_removed": (tree.get("endpoints_removed") or [])[:limit],
                  "endpoint_rename_candidates": tree.get("endpoint_rename_candidates") or [],
                  "field_moves": (tree.get("field_moves") or [])[:limit],
                  "rename_candidates": renames[:limit],
                  "options_changed": options[:limit]}
                 if tree else None),
        "tree_reason": ch.get("tree_reason") or "",
        "channel_moves": len(ch.get("channel_moves") or []),
    }


def channels_doc(product: str, version: str, limit: int = 200) -> dict:
    """``channels_at`` of one build: the summary plus the fields worth reading
    (CLI only, hidden, REST only, vendor-doc conflicts), capped at ``limit``."""
    from .services import api_library

    ch = api_library.channels_at(product, version)
    picks = {"cli_only": [], "hidden": [], "rest_only": [], "doc_conflict": []}
    for key, ep in sorted(ch["endpoints"].items()):
        for f, x in sorted(ep["fields"].items()):
            if x["channel"] in ("cli_only", "hidden", "rest_only"):
                picks[x["channel"]].append("%s.%s" % (key, f))
            if x.get("doc_conflict"):
                picks["doc_conflict"].append("%s.%s" % (key, f))
    return {"product": product, "version": ch["version"], "build": ch["build"],
            "summary": ch["summary"], "endpoints": len(ch["endpoints"]),
            **{k: v[:limit] for k, v in picks.items()},
            "truncated": {k: len(v) > limit for k, v in picks.items()}}


@apilib_cli.command("compat")
@click.argument("product")
@click.argument("base")
@click.argument("target")
def compat_cmd(product, base, target):
    """Compare two builds of PRODUCT through both channels (JSON)."""
    from .services import api_library
    if product not in api_library.PRODUCTS:
        raise click.ClickException("unknown product %r" % product)
    _print(compat_doc(product, base, target))


@apilib_cli.command("channels")
@click.argument("product")
@click.argument("version")
def channels_cmd(product, version):
    """Per-field channel classification of one build of PRODUCT (JSON)."""
    from .services import api_library
    if product not in api_library.PRODUCTS:
        raise click.ClickException("unknown product %r" % product)
    _print(channels_doc(product, version))


@apilib_cli.command("migration-report")
@click.argument("appliance")
@click.option("--target", required=True, help="Target firmware build, e.g. 8.0.6.")
@click.option("--backup", "backup_id", type=int, default=None,
              help="Vault backup id to read (default: the newest usable dump).")
def migration_report_cmd(appliance, target, backup_id):
    """Check APPLIANCE's newest configuration dump against a target build.
    APPLIANCE is an id or a name. Read-only; prints the report as JSON."""
    from .models import Appliance
    from .services import migration_report
    ap = None
    if str(appliance).isdigit():
        ap = Appliance.query.get(int(appliance))
    if ap is None:
        ap = Appliance.query.filter_by(name=appliance).first()
    if ap is None:
        raise click.ClickException("no appliance %r" % appliance)
    click.echo(migration_report.to_json(
        migration_report.for_appliance(ap, target, backup_id=backup_id)))


@apilib_cli.command("adapter-harvest")
@click.argument("appliance")
@click.option("--ssh-secret-env", default="",
              help="FortiAuthenticator: name of an environment variable holding the "
                   "CLI password (SATOM stores the REST API key, not a CLI login).")
def adapter_harvest_cmd(appliance, ssh_secret_env):
    """Harvest one appliance through its product's schema adapter
    (services.schema_adapters). APPLIANCE is an id or a name."""
    import os

    from .models import Appliance
    from .services import schema_adapters as sa
    ap = Appliance.query.get(int(appliance)) if str(appliance).isdigit() else None
    ap = ap or Appliance.query.filter_by(name=appliance).first()
    if ap is None:
        raise click.ClickException("no appliance %r" % appliance)
    kw = {}
    if ssh_secret_env:
        if not os.environ.get(ssh_secret_env):
            raise click.ClickException("environment variable %s is empty" % ssh_secret_env)
        kw["ssh_secret"] = os.environ[ssh_secret_env]
    res = sa.harvest(ap, **kw)
    _print(res)
    if not res.get("ok"):
        raise SystemExit(1)


@apilib_cli.command("schema-import")
@click.option("--product", required=True, type=click.Choice(["fortigate", "fortianalyzer"]))
@click.option("--version", "version", required=True, help="Exact build, e.g. 8.0.1.")
@click.option("--build", "build", default="", help="Build token, e.g. build0245.")
@click.option("--label", default="import", help="Witness name recorded with the evidence.")
@click.option("--tree", "tree_path", default=None, type=click.Path(exists=True, dir_okay=False),
              help="FortiGate: saved `tree` output (cli_tree evidence).")
@click.option("--schema", "schema_path", default=None,
              type=click.Path(exists=True),
              help="FortiGate: ?action=schema JSON, or a directory of per-table answers "
                   "(<path>__<name>.json [+ fetch_summary.json]); "
                   "FortiAnalyzer: {url: syntax response}.")
def schema_import_cmd(product, version, build, label, tree_path, schema_path):
    """Import saved schema captures of a product SATOM does not read live."""
    import json
    from datetime import datetime

    from .services import api_library, cli_schema
    from .services.schema_adapters import fortianalyzer, fortigate
    now = datetime.utcnow().isoformat(timespec="seconds")
    device = {"name": label}
    out = []
    if tree_path:
        if product != "fortigate":
            raise click.ClickException("--tree is FortiGate only (FortiAnalyzer has no tree)")
        text = open(tree_path, encoding="utf-8", errors="replace").read()
        doc = cli_schema.evidence_from_cli_tree(product, version, build, text, device,
                                                "import:%s:tree" % label, captured_at=now)
        out.append({"tree": api_library.ingest(doc, raw={"doc": doc, "tree_text": text}),
                    "healthy": doc["healthy"], "skip_reason": doc["skip_reason"]})
    if schema_path:
        errors = {}
        if os.path.isdir(schema_path):
            if product != "fortigate":
                raise click.ClickException("a capture directory is FortiGate only")
            body, errors = fortigate.load_capture_dir(schema_path)
        else:
            body = json.load(open(schema_path, encoding="utf-8"))
        if product == "fortigate":
            doc = fortigate.evidence_from_schema(body, version, build, device,
                                                 "import:%s:schema" % label, captured_at=now,
                                                 errors=errors)
        else:
            doc = fortianalyzer.evidence_from_syntax(body, version, build, device,
                                                     "import:%s:schema" % label, captured_at=now)
        out.append({"schema": api_library.ingest(doc), "healthy": doc["healthy"],
                    "skip_reason": doc["skip_reason"]})
    if not out:
        raise click.ClickException("nothing to import: give --tree and/or --schema")
    _print(out)


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


# ---------------------------------------------------------------------------
# ``flask apilib baseline ...`` — the endpoint registry's seed (docs §9)
# ---------------------------------------------------------------------------

baseline_cli = AppGroup("baseline", help="Endpoint baselines: the registry seed, "
                                          "pinned to a firmware build.")
apilib_cli.add_command(baseline_cli)


def _actor() -> str:
    return "cli:%s" % (os.environ.get("SUDO_USER") or os.environ.get("USER") or "unknown")


def _baseline_products(product):
    from .services import api_baseline
    if product and product not in api_baseline.products():
        raise click.ClickException("unknown product %r (known: %s)"
                                   % (product, ", ".join(api_baseline.products())))
    return [product] if product else list(api_baseline.products())


@baseline_cli.command("status")
def baseline_status_cmd():
    """The active baseline of every registry product."""
    from .services import api_baseline
    for p in api_baseline.products():
        s = api_baseline.summary(api_baseline.active(p))
        if s is None:
            click.echo("%-20s (no baseline)" % p)
            continue
        click.echo("%-20s %-8s %-8s %-8s entries=%-4d %s  applied=%s  sha=%s" % (
            p, s["version"], s["api_version"], s["method"], s["entries"],
            " ".join("%s:%d" % kv for kv in sorted(s["by_provenance"].items())),
            "yes" if s["applied_at"] else "NO", s["sha256"][:12]))


@baseline_cli.command("promote")
@click.option("--product", required=True)
@click.option("--build", "version", required=True,
              help="Firmware build to pin the baseline to (e.g. 7.6.8). Must be measured.")
@click.option("--apply", "do_apply", is_flag=True,
              help="Write the baseline and reconcile the registry. Without it: dry run.")
@click.option("--export", "do_export", is_flag=True,
              help="Also write app/registry/baselines/<product>.json (release work).")
@click.option("--note", default="", help="Why this baseline was promoted.")
def baseline_promote_cmd(product, version, do_apply, do_export, note):
    """Promote what the library measured on BUILD as PRODUCT's baseline."""
    from .services import api_baseline
    _baseline_products(product)
    try:
        plan = api_baseline.plan_promotion(product, version)
    except ValueError as exc:
        raise click.ClickException(str(exc))
    d = plan["diff"]
    prev = plan["previous"]
    click.echo("%s: %s -> %s  (%d entries: %s)" % (
        product, (prev or {}).get("version", "none"), plan["version"], len(plan["entries"]),
        " ".join("%s:%d" % kv for kv in sorted(plan["by_provenance"].items()))))
    for name in d["added"]:
        click.echo("  + %s" % name)
    for name in d["removed"]:
        click.echo("  - %s   (measured absent on %s)" % (name, plan["version"]))
    for c in d["urn_changed"]:
        click.echo("  ~ %s   %s -> %s" % (c["name"], c["from"], c["to"]))
    if plan["identical"]:
        click.echo("identical to the active baseline; nothing to promote.")
        return
    if not do_apply:
        click.echo("dry run: re-run with --apply to promote.")
        return
    res = api_baseline.promote(product, version, actor=_actor(), note=note)
    _print({"baseline": res["baseline"], "created": res["created"],
            "applied": res.get("applied")})
    if do_export:
        click.echo("exported %s" % api_baseline.export(product))


@baseline_cli.command("adopt")
@click.option("--product", required=True)
@click.option("--build", "version", required=True,
              help="Firmware build the legacy map was written against.")
@click.argument("path", type=click.Path(exists=True, dir_okay=False))
@click.option("--note", default="")
def baseline_adopt_cmd(product, version, path, note):
    """One-time: adopt a legacy flat ``name: urn`` map as the FIRST baseline."""
    import yaml

    from .services import api_baseline
    _baseline_products(product)
    with open(path, encoding="utf-8") as fh:
        mapping = yaml.safe_load(fh) or {}
    if not isinstance(mapping, dict):
        raise click.ClickException("%s is not a flat name: urn map" % path)
    try:
        res = api_baseline.adopt(product, version, mapping, actor=_actor(), note=note)
    except ValueError as exc:
        raise click.ClickException(str(exc))
    _print(res)


@baseline_cli.command("export")
@click.option("--product", default=None, help="One product (default: all).")
def baseline_export_cmd(product):
    """Write the active baseline(s) to app/registry/baselines/."""
    from .services import api_baseline
    for p in _baseline_products(product):
        try:
            click.echo("exported %s" % api_baseline.export(p))
        except ValueError as exc:
            click.echo("%s: %s" % (p, exc))


@baseline_cli.command("apply")
@click.option("--product", default=None, help="One product (default: all).")
def baseline_apply_cmd(product):
    """Reconcile the registry to the active baseline (operator rows spared)."""
    from .services import api_baseline
    out = {}
    for p in _baseline_products(product):
        b = api_baseline.active(p)
        out[p] = api_baseline.apply(b) if b is not None else "no baseline"
    _print(out)


@baseline_cli.command("check")
@click.option("--product", default=None, help="One product (default: all).")
def baseline_check_cmd(product):
    """Drift: registry vs baseline vs the evidence of every build the fleet runs.

    Exit status 1 when anything drifted, so it can gate a release.
    """
    from .services import api_baseline
    reports = [api_baseline.check(p) for p in _baseline_products(product)]
    _print(reports)
    if not all(r["ok"] for r in reports):
        raise SystemExit(1)


@baseline_cli.command("resolve")
@click.option("--product", required=True)
@click.option("--build", "version", default=None, help="Firmware build (optional).")
@click.argument("name")
def baseline_resolve_cmd(product, version, name):
    """How NAME resolves on BUILD, and on what authority."""
    from .services import api_baseline
    _baseline_products(product)
    _print(api_baseline.resolve_at(product, name, version))


# ---------------------------------------------------------------------------
# ``flask apilib pack ...`` — signed API packs for offline nodes (docs §11)
# ---------------------------------------------------------------------------

pack_cli = AppGroup("pack", help="Signed API packs: export this node's API knowledge, "
                                  "inspect a pack, import it.")
apilib_cli.add_command(pack_cli)


@pack_cli.command("export")
@click.option("--version", "version", required=True, help="Pack version (normally the release).")
@click.option("--out", "out_dir", required=True, type=click.Path(file_okay=False))
@click.option("--product", "products", multiple=True, help="Limit to one product (repeatable).")
@click.option("--section", "sections", multiple=True,
              type=click.Choice(["library", "docs", "cli-coverage"]),
              help="Limit to one section (repeatable; default: all).")
@click.option("--notes", default="")
@click.option("--sign-key", default=None, type=click.Path(exists=True, dir_okay=False),
              help="Private key to sign with (else sign later with sign_update_package.py).")
@click.option("--passphrase-file", default=None, type=click.Path(exists=True, dir_okay=False))
def pack_export_cmd(version, out_dir, products, sections, notes, sign_key, passphrase_file):
    """Build satom-apipack-VERSION.tar.gz (anonymised; refused on any leak)."""
    from .services import api_pack
    try:
        res = api_pack.export_pack(out_dir, version, products=list(products) or None,
                                   sections=list(sections) or api_pack.SECTIONS,
                                   notes=notes, sign_key=sign_key,
                                   passphrase_file=passphrase_file)
    except api_pack.PackError as exc:
        raise click.ClickException(str(exc))
    _print(res)


def _trust_opt(f):
    return click.option("--trust-dir", default=None, type=click.Path(file_okay=False),
                        help="Trust store (default: the update-package trust store).")(f)


@pack_cli.command("inspect")
@click.argument("path", type=click.Path(exists=True, dir_okay=False))
@_trust_opt
def pack_inspect_cmd(path, trust_dir):
    """Verify a pack and show what importing each item would do."""
    from .services import api_pack
    try:
        res = api_pack.inspect_pack(path, trust_dir=trust_dir)
    except api_pack.PackError as exc:
        raise click.ClickException(str(exc))
    click.echo("pack %s  built %s  signed by %s" % (
        res["version"], res["built_at"], res["signed_by"]["fingerprint"]))
    for it in res["items"]:
        extra = it.get("new_versions") or it.get("new_objects") or ""
        click.echo("  %-8s %-62s %s" % (it["state"], it["id"],
                                        ("+" + ",".join(extra)) if extra else ""))


@pack_cli.command("import")
@click.argument("path", type=click.Path(exists=True, dir_okay=False))
@click.option("--product", "products", multiple=True)
@click.option("--section", "sections", multiple=True,
              type=click.Choice(["library", "docs", "cli-coverage"]))
@click.option("--item", "ids", multiple=True, help="One item id from `inspect` (repeatable).")
@click.option("--dry-run", is_flag=True)
@_trust_opt
def pack_import_cmd(path, products, sections, ids, dry_run, trust_dir):
    """Import the selected NEW items. Local measurements are never overwritten."""
    from .services import api_pack
    try:
        res = api_pack.import_pack(path, trust_dir=trust_dir, products=products,
                                   sections=sections, ids=ids, dry_run=dry_run,
                                   actor=_actor())
    except api_pack.PackError as exc:
        raise click.ClickException(str(exc))
    _print(res)
    if res["errors"]:
        raise SystemExit(1)
