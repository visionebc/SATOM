"""Administrator datasets generated from the device cache (2026-10-25).

The ``objects`` source already gives one dataset per cached object type (603
on the lab fleet), but each is one type alone: a policy's source addresses
are a separate list that names the policy only by ``parent_id``, an address
group's members name addresses only by their name. What a plugin author
usually wants is the JOIN, and building ~300 of them by hand in the query
builder is the job nobody does. Requested: "create as many as you can,
trying to cover everything, divided by ADOM".

:func:`generate` writes them as ordinary administrator datasets (model
``PluginDataset``, source :data:`SOURCE`, the ADOM of their product), built
with the same query-builder spec an administrator would save and checked by
the same ``clean_admin``. Three families:

* **list + parent** -- every sub-object type with its parent's identity and
  main fields (each policy's source addresses with the policy's ID and name);
* **reference resolved** -- every field that names another object, with that
  object's fields (a virtual server with its pool, a group member with the
  address);
* **chains** -- the questions a fleet asks, written once: which rules use an
  address, which groups hold it, which rules use a service, which pool member
  is which real server...

Never overwrites: a key that exists (generated before, or edited by an
administrator) is left alone, so running it again only adds what the cache
gained. Deleting one and running again brings it back -- by design, the
button says so.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

SOURCE = "generated from the device cache"
LIMIT = 500
PARENT_FIELDS = 5
CHILD_FIELDS = 12
REF_SOURCE_FIELDS = 6
REF_TARGET_FIELDS = 10

#: ``(slug, product, label, description, base, [(join table, from table,
#: from col, to col)], [(table, col)])`` -- tables are object-table keys.
CHAINS: list[tuple] = [
    ("fortigate_address_in_rules_as_source", "fortigate",
     "FortiGate: rules that use an address as source",
     "Each IPv4 address object with every firewall policy that lists it as a source "
     "address (directly, not through a group): device, address, subnet/range/FQDN, "
     "policy ID, name, UUID, action and status. Addresses no rule uses come with empty "
     "policy columns.",
     "fortigate_firewall_address",
     [("fortigate_firewall_policy__srcaddr", "fortigate_firewall_address", "object_key", "name_ref"),
      ("fortigate_firewall_policy", "fortigate_firewall_policy__srcaddr", "parent_id", "id")],
     [("fortigate_firewall_address", c) for c in ("device", "name", "type", "subnet", "start_ip",
                                                   "end_ip", "fqdn", "uuid")]
     + [("fortigate_firewall_policy", c) for c in ("policyid", "name", "uuid", "action", "status",
                                                   "schedule", "comments")]),
    ("fortigate_address_in_rules_as_destination", "fortigate",
     "FortiGate: rules that use an address as destination",
     "Each IPv4 address object with every firewall policy that lists it as a destination "
     "address (directly): device, address, subnet/range/FQDN, policy ID, name, UUID, "
     "action and status.",
     "fortigate_firewall_address",
     [("fortigate_firewall_policy__dstaddr", "fortigate_firewall_address", "object_key", "name_ref"),
      ("fortigate_firewall_policy", "fortigate_firewall_policy__dstaddr", "parent_id", "id")],
     [("fortigate_firewall_address", c) for c in ("device", "name", "type", "subnet", "start_ip",
                                                   "end_ip", "fqdn", "uuid")]
     + [("fortigate_firewall_policy", c) for c in ("policyid", "name", "uuid", "action", "status",
                                                   "schedule", "comments")]),
    ("fortigate_address_groups_of_an_address", "fortigate",
     "FortiGate: the address groups each address is in",
     "Each IPv4 address object with the address groups that hold it as a member.",
     "fortigate_firewall_address",
     [("fortigate_firewall_addrgrp__member", "fortigate_firewall_address", "object_key", "name_ref"),
      ("fortigate_firewall_addrgrp", "fortigate_firewall_addrgrp__member", "parent_id", "id")],
     [("fortigate_firewall_address", c) for c in ("device", "name", "type", "subnet", "fqdn", "uuid")]
     + [("fortigate_firewall_addrgrp", c) for c in ("name", "uuid", "comment")]),
    ("fortigate_group_in_rules_as_source", "fortigate",
     "FortiGate: rules that use an address group as source",
     "Each address group with every firewall policy that lists it as a source.",
     "fortigate_firewall_addrgrp",
     [("fortigate_firewall_policy__srcaddr", "fortigate_firewall_addrgrp", "object_key", "name_ref"),
      ("fortigate_firewall_policy", "fortigate_firewall_policy__srcaddr", "parent_id", "id")],
     [("fortigate_firewall_addrgrp", c) for c in ("device", "name", "uuid", "comment")]
     + [("fortigate_firewall_policy", c) for c in ("policyid", "name", "uuid", "action", "status")]),
    ("fortigate_group_in_rules_as_destination", "fortigate",
     "FortiGate: rules that use an address group as destination",
     "Each address group with every firewall policy that lists it as a destination.",
     "fortigate_firewall_addrgrp",
     [("fortigate_firewall_policy__dstaddr", "fortigate_firewall_addrgrp", "object_key", "name_ref"),
      ("fortigate_firewall_policy", "fortigate_firewall_policy__dstaddr", "parent_id", "id")],
     [("fortigate_firewall_addrgrp", c) for c in ("device", "name", "uuid", "comment")]
     + [("fortigate_firewall_policy", c) for c in ("policyid", "name", "uuid", "action", "status")]),
    ("fortigate_service_in_rules", "fortigate",
     "FortiGate: rules that allow a service",
     "Each custom service (protocol and ports) with every firewall policy that lists it.",
     "fortigate_firewall_service_custom",
     [("fortigate_firewall_policy__service", "fortigate_firewall_service_custom", "object_key",
       "name_ref"),
      ("fortigate_firewall_policy", "fortigate_firewall_policy__service", "parent_id", "id")],
     [("fortigate_firewall_service_custom", c) for c in ("device", "name", "protocol",
                                                         "tcp_portrange", "udp_portrange")]
     + [("fortigate_firewall_policy", c) for c in ("policyid", "name", "uuid", "action", "status")]),
    ("fortigate_interface_in_rules_as_source", "fortigate",
     "FortiGate: rules by incoming interface",
     "Each interface with every firewall policy whose incoming interface it is.",
     "fortigate_system_interface",
     [("fortigate_firewall_policy__srcintf", "fortigate_system_interface", "object_key", "name_ref"),
      ("fortigate_firewall_policy", "fortigate_firewall_policy__srcintf", "parent_id", "id")],
     [("fortigate_system_interface", c) for c in ("device", "name", "ip", "status", "type")]
     + [("fortigate_firewall_policy", c) for c in ("policyid", "name", "action", "status")]),
    ("fortiadc_virtual_server_pool_members", "fortiadc",
     "FortiADC: virtual servers with their pool members",
     "Each virtual server with its pool and every member of that pool (address, port, "
     "weight, status).",
     "fortiadc_load_balance_virtual_server",
     [("fortiadc_load_balance_pool", "fortiadc_load_balance_virtual_server", "pool_ref", "object_key"),
      ("fortiadc_load_balance_pool__pool_member", "fortiadc_load_balance_pool", "id", "parent_id")],
     [("fortiadc_load_balance_virtual_server", c) for c in ("device", "mkey", "status", "address",
                                                            "port", "protocol", "pool")]
     + [("fortiadc_load_balance_pool__pool_member", c) for c in ("mkey", "address", "port",
                                                                 "weight", "status")]),
    ("fortiauthenticator_users_with_groups", "fortiauthenticator",
     "FortiAuthenticator: local users with their groups",
     "Each local user (username, e-mail, active, token) with every user group it belongs to.",
     "fortiauthenticator_auth_local_users",
     [("fortiauthenticator_auth_local_group_members", "fortiauthenticator_auth_local_users",
       "resource_uri_key", "user_ref"),
      ("fortiauthenticator_auth_user_groups", "fortiauthenticator_auth_local_group_members",
       "group_ref", "resource_uri_key")],
     [("fortiauthenticator_auth_local_users", c) for c in ("device", "username", "email", "active",
                                                           "mobile_number", "token_type")]
     + [("fortiauthenticator_auth_user_groups", c) for c in ("name", "password_policy")]),
    ("fortiauthenticator_radius_clients_with_policies", "fortiauthenticator",
     "FortiAuthenticator: RADIUS clients with their policies",
     "Each RADIUS client (the device allowed to authenticate against the FortiAuthenticator) "
     "with the RADIUS policies it uses.",
     "fortiauthenticator_radius_clients",
     [("fortiauthenticator_radius_policy_client", "fortiauthenticator_radius_clients",
       "resource_uri_key", "client_ref"),
      ("fortiauthenticator_radius_policies", "fortiauthenticator_radius_policy_client",
       "policy_ref", "resource_uri_key")],
     [("fortiauthenticator_radius_clients", c) for c in ("device", "name", "address")]
     + [("fortiauthenticator_radius_policies", c) for c in ("name",)]),
]


def _slug(text: str) -> str:
    """An admin key slug (``^[a-z][a-z0-9_]{1,59}$``): long ones keep a hash."""
    from .plugin_datasets import ident
    s = ident(text).strip("_") or "dataset"
    if not s[0].isalpha():
        s = "d_" + s
    if len(s) > 60:
        s = s[:51].rstrip("_") + "_" + hashlib.sha1(text.encode()).hexdigest()[:8]
    return s


def _fields(t: dict, n: int, skip=()) -> list[str]:
    sens = {c["name"] for c in t["cols"] if c.get("sensitive")}
    return [c for c in t["object"]["fields"] if c not in sens and c not in skip][:n]


def _spec(base: str, joins: list[tuple], cols: list[tuple]) -> dict:
    return {"base": base,
            "joins": [{"table": jt, "from_table": ft, "from_col": fc, "to_col": tc}
                      for jt, ft, fc, tc in joins],
            "columns": [{"table": t, "col": c} for t, c in cols],
            "limit": LIMIT}


def candidates() -> list[dict]:
    """Every dataset :func:`generate` would write, from the cache as it is now:
    ``[{key, label, description, product, spec}]`` (not yet checked)."""
    from . import object_tables as OT
    tables = OT.tables()
    out: list[dict] = []
    # chains first: they are the ones people look for
    for slug, product, label, desc, base, joins, cols in CHAINS:
        needed = {base} | {j[0] for j in joins}
        if not needed <= set(tables):
            continue
        # a column this cache lacks, or a secret one, is left out
        have = [(t, c) for t, c in cols
                if c in {x["name"] for x in tables[t]["cols"] if not x.get("sensitive")}]
        out.append({"key": slug, "product": product, "label": label, "description": desc,
                    "spec": _spec(base, joins, have), "family": "chain"})
    for name, t in sorted(tables.items()):
        ob = t["object"]
        product = ob["product"]
        prod_label = OT.PRODUCT_LABEL[product]
        parent = next((e["to_table"] for e in t["edges"] if e["from_col"] == "parent_id"), None)
        if parent:
            p = tables[parent]
            pcols = [("device"), ("mkey")] + _fields(p, PARENT_FIELDS, skip=("mkey",))
            ccols = ["mkey"] + _fields(t, CHILD_FIELDS, skip=("mkey",))
            lst = ob["logical"].rsplit("/", 1)[1].replace("_", " ").replace("-", " ")
            out.append({
                "key": _slug(name + "_with_parent"), "product": product,
                "label": "%s with its %s" % (p["label"], lst),
                "description": "Every entry of the %s list of each %s, with the %s's identity "
                               "(device, key) and main fields. %s" % (
                                   lst, p["label"], p["label"].split(" ", 1)[-1],
                                   "Built from the device cache; one row per entry."),
                "spec": _spec(name, [(parent, name, "parent_id", "id")],
                              [(parent, c) for c in pcols] + [(name, c) for c in ccols]),
                "family": "parent"})
        for e in t["edges"]:
            if not e["from_col"].endswith(OT.REF_SUFFIX) or not (
                    e["to_col"] == "object_key" or e["to_col"].endswith(OT.KEY_SUFFIX)):
                continue
            target = tables[e["to_table"]]
            field = e["from_col"][:-len(OT.REF_SUFFIX)]
            scols = ["device", "mkey"] + _fields(t, REF_SOURCE_FIELDS, skip=("mkey",))
            if field not in scols:
                scols.append(field)
            tcols = ["mkey"] + _fields(target, REF_TARGET_FIELDS, skip=("mkey",))
            tshort = target["object"]["logical"].replace("/", "_")
            out.append({
                "key": _slug("%s__%s__%s" % (name, field, tshort)), "product": product,
                "label": "%s with the %s its %s names" % (t["label"],
                                                         target["label"][len(prod_label) + 1:],
                                                         field),
                "description": "Each %s with the %s object its %s field names (same device), "
                               "and that object's main fields. Rows whose %s names something "
                               "else come with empty target columns." % (
                                   t["label"], target["label"], field, field),
                "spec": _spec(name, [(e["to_table"], name, e["from_col"], e["to_col"])],
                              [(name, c) for c in scols] + [(e["to_table"], c) for c in tcols]),
                "family": "reference"})
    seen, uniq = set(), []
    for c in out:
        if c["key"] not in seen:
            seen.add(c["key"])
            uniq.append(c)
    return uniq


def generate(*, by: str) -> dict[str, Any]:
    """Write every candidate whose key does not exist yet, published, in its
    product's ADOM. Returns ``{created, existing, refused: [(key, why)],
    by_product: {product: n}}``."""
    from ..extensions import db
    from ..models import PluginDataset
    from . import plugin_datasets as PD
    from . import report_builder as RB
    have = {k for (k,) in db.session.query(PluginDataset.key).all()}
    created, existing, refused, per = 0, 0, [], {}
    with RB.schema_snapshot():
        for c in candidates():
            key = PD.admin_key(c["key"])
            if key in have:
                existing += 1
                continue
            try:
                clean = PD.clean_admin(c["key"], c["label"], c["description"], c["spec"],
                                       c["product"])
            except PD.DatasetError as exc:
                refused.append((key, str(exc)[:200]))
                continue
            db.session.add(PluginDataset(key=clean["key"], label=clean["label"],
                                         description=clean["description"],
                                         spec=json.dumps(clean["spec"]),
                                         product=clean["product"], status="published",
                                         source=SOURCE, created_by=by, updated_by=by))
            have.add(clean["key"])
            created += 1
            per[c["product"]] = per.get(c["product"], 0) + 1
    db.session.commit()
    return {"created": created, "existing": existing, "refused": refused, "by_product": per}
