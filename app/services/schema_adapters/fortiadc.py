"""FortiADC: ``tree`` + ``show full-configuration`` + a REST shape probe.

Same implementation as FortiWeb (``services.schema_harvest``). Measured on
fortiadc10 (FortiADC-VM 7.6.7 build0676, 2026-10-13), not assumed:

* ``tree`` prints the FortiWeb format (``[table(id)]``, ``{singleton(id)}``,
  ``field(id) <type>`` or the option list), NOT the FortiOS one the first
  version of this adapter assumed: ``cli_schema.parse_tree`` detected
  ``fortiweb`` and read 527 objects (398 tables, 129 singletons), 3 649
  fields, 1 281 enums, 0 unmapped.
* ``show full-configuration`` (fresh SSH capture): 315 blocks, 1 147 field
  names, all of them in the tree (0 hidden, 0 unmapped).
* The CLI -> REST rule (``config load-balance virtual-server`` ->
  ``/api/load_balance_virtual_server``; a table in a table ->
  ``<parent>_child_<table>``, ``cli_schema.PATH_RULE_STATUS``): 224 of the
  225 REST endpoints the box's own sweep read ``ok`` land on a tree object
  under the rule (the odd one, ``system_certificate_ocsp_stapling``, has no
  ``config`` of that name), and the 19 child tables the depth capture read
  at ``/api/<parent>_child_<table>?pkey=`` are all tree objects under it.

What the measurement ALSO showed (:func:`field_twins`, ``api_library``):
FortiADC's REST does not always spell a field the way its CLI does. In 7.6.7
the REST rows of 226 joined objects carry 324 fields that are a CLI
attribute with ``_`` for ``-`` (REST ``direct_route_ip`` = CLI
``direct-route-ip``), ``mkey`` for the table key, and some outright renames
(REST ``pool`` = CLI ``load-balance-pool``, ``domain-name`` =
``domainname``) that no rule derives. So on this product a CLI field REST
does not name is NOT "CLI only": it may be served under another name. The
renames are joined only where they were MEASURED, per build
(``fortiadc_renames``: REST rows against ``show full-configuration`` of
fortiadc10 7.6.7 and fortiadc11 8.0.4, value by value).

The knowledge pack's ``cli_tree`` (satom-harvester) keys FortiADC objects by
the FortiWeb rule (``load-balance/pool``, ``firewall/policy/rule``); SATOM's
own harvest and the REST sweep key them by this product's rule
(:func:`tree_channel_keys` re-keys the pack's at read time).
"""
from __future__ import annotations

from .. import cli_schema
from . import Adapter, Capabilities, Verification, register

PRODUCT = "fortiadc"
#: What is still not checked (the UI shows these reasons). Empty since the
#: harvest of fortiadc10 measured the tree, the dump and the path rule.
UNVERIFIED: dict = {}
#: SATOM's own harvest against a real FortiADC (Schema builds harvest = cli_tree
#: evidence #95 + cli_full #96 on a1, next to the box's REST sweep #77).
VERIFIED_ON = {"date": "2026-10-13", "device": "fortiadc10 (lab)", "build": "7.6.7 build0676"}
#: REST bookkeeping of a FortiADC row (``api_library.REST_META``): edit/delete
#: flags of the GUI, never configuration, never in the tree.
REST_META_EXACT = frozenset({"_nondeletable", "_noneditable"})
#: The REST name of a table's key, whatever the CLI calls it (``name``, ``id``).
REST_MKEY = "mkey"


def tree_channel_keys(objects: dict) -> dict:
    """``{CLI evidence key: REST channel key}`` for a build's CLI objects.

    ``objects`` is the CLI evidence's ``summary.objects`` (``cli_path``,
    ``kind``, ``parent`` = the parent's key). The knowledge pack keyed
    FortiADC objects by the FortiWeb rule (``load-balance/pool``) while the
    REST sweep keys them ``load_balance_pool``: joined on the key, nothing
    met and every field read ``rest_only`` or ``unknown`` (fortiadc10 7.6.7,
    2026-10-13: 10 fields "both" out of 5 402). The REST key follows from the
    CLI path and which words of it are objects, so it is computed from the
    metadata whatever rule wrote the key. An object whose metadata is
    incomplete (no CLI path, a parent that is not one of the objects, a
    path the rule does not map) is left out: the caller keeps its key.
    """
    objs = {k: m for k, m in (objects or {}).items()
            if isinstance(m, dict) and m.get("cli_path")}
    kind_of = {m["cli_path"]: m.get("kind") or cli_schema.KIND_OBJECT for m in objs.values()}
    out: dict = {}
    for key, meta in objs.items():
        words = meta["cli_path"].split()
        parent = meta.get("parent") or ""
        if parent:
            pmeta = objs.get(parent)
            if pmeta is None and parent in kind_of:
                pmeta = {"cli_path": parent}
            if pmeta is None or not meta["cli_path"].startswith(pmeta["cli_path"] + " "):
                continue
        chain = [kind_of.get(" ".join(words[:i + 1]), cli_schema.KIND_NAMESPACE)
                 for i in range(len(words))]
        rk = cli_schema.rest_path(PRODUCT, meta["cli_path"], chain)
        if rk:
            out[key] = rk
    return out


def _spelling(name: str) -> str:
    return str(name or "").lower().replace("_", "-")


def field_twins(rest_names, cli_names, mkey: str = "", renames=None) -> dict:
    """``{REST field name: CLI field name}`` for the fields of ONE object
    both channels name, spelled differently.

    What the spelling proves: the same name with ``_`` for ``-``
    (REST ``direct_route_ip`` = CLI ``direct-route-ip``), and REST ``mkey``
    = the table key the tree names (``name``). A pair is made only when
    neither name is already on the other side, and one-to-one (two REST
    names that fold to one CLI name make no pair). Renames
    (``pool`` / ``load-balance-pool``) are never guessed: only ``renames``,
    the pairs MEASURED on this object's build (``fortiadc_renames``), join
    them, under the same conditions.
    """
    rest, cli = set(rest_names or ()), set(cli_names or ())
    out: dict = {}
    if mkey and REST_MKEY in rest and REST_MKEY not in cli and mkey in cli and mkey not in rest:
        out[REST_MKEY] = mkey
    for r, c in sorted((renames or {}).items()):
        if r in rest and r not in cli and c in cli and c not in rest \
                and r not in out and c not in out.values():
            out[r] = c
    cli_free = {_spelling(c): c for c in sorted(cli - rest - set(out.values()))}
    seen: dict = {}
    for r in sorted(rest - cli):
        if r in out:
            continue
        c = cli_free.get(_spelling(r))
        if c is None or c in out.values():
            continue
        seen.setdefault(c, []).append(r)
    for c, rs in seen.items():
        if len(rs) == 1:
            out[rs[0]] = c
    return out


def _harvest(appliance, **kw):
    from .. import schema_harvest
    res = schema_harvest.harvest(appliance, **kw)
    res["unverified"] = sorted(UNVERIFIED)
    return res


ADAPTER = register(Adapter(
    product=PRODUCT, label="FortiADC",
    capabilities=Capabilities(tree=True, show_full=True, rest_schema=False, rest_probe=True),
    verified_on=(Verification(VERIFIED_ON["date"], VERIFIED_ON["device"], VERIFIED_ON["build"],
                              "tree, show full-configuration and the CLI -> REST path rule"),),
    unverified=UNVERIFIED, live=True,
    notes="tree prints the FortiWeb format (CLI ids, types, options); REST paths are "
          "underscore paths (/api/load_balance_virtual_server, <parent>_child_<table>). "
          "REST spells some fields differently from the CLI (direct_route_ip / "
          "direct-route-ip, mkey / name, pool / load-balance-pool): spelling twins and "
          "the renames measured on the build are joined, and any other CLI field REST "
          "does not name reads unknown, never CLI only. The REST shape probe "
          "(schema_harvest._probe_rest_adc) reads the tree objects the rediscovery sweep "
          "does not, a child table by ?pkey=; a 404 at a child path is not recorded "
          "(some children are served only inside the parent row)."),
    _harvest)
