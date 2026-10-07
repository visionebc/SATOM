"""``flask knowledge ...`` — knowledge packs from the console.

The operator CLI (``satom execute knowledge fetch`` / ``satom show knowledge``)
runs these as the service account, the same way ``satom execute apipack
import`` runs ``flask apilib pack import``: files written under data/ stay
the web worker's. Output is one JSON document so the CLI can render it.
"""
from __future__ import annotations

import json

import click
from flask.cli import AppGroup

knowledge_cli = AppGroup("knowledge", help="Knowledge packs: check the feed, download, import.")


def _print(obj) -> None:
    click.echo(json.dumps(obj, indent=1, sort_keys=True, default=str))


@knowledge_cli.command("show")
def show_cmd():
    """Installed packs per lane, the mode, the feed and the last result. No network."""
    from .services import knowledge_fetch as kf
    st = kf.state()
    st.pop("modes", None)
    st.pop("lane_labels", None)
    st["freshness"] = kf.freshness()
    _print(st)


@knowledge_cli.command("fetch")
@click.option("--feed", "feed", default="", help="https URL of a latest.json (default: the setting).")
@click.option("--download/--check-only", "download", default=False,
              help="Download the pack when the feed offers a newer one.")
@click.option("--import", "do_import", is_flag=True, default=False,
              help="Download AND import it (signature verified by the import).")
@click.option("--actor", default="cli", help="Recorded in the import log.")
def fetch_cmd(feed, download, do_import, actor):
    """Check the feed; optionally download and import. Exit 1 on a failure."""
    from .services import knowledge_fetch as kf
    if feed and not feed.lower().startswith("https://"):
        raise click.ClickException("--feed must be an https:// URL")
    res = kf.run(url=feed, do_download=download or do_import, do_import=do_import,
                 actor=actor, trigger="cli")
    _print(res)
    if res["status"] in (kf.ST_ERROR, kf.ST_FAILED, kf.ST_STANDBY) and (download or do_import):
        raise SystemExit(1)
